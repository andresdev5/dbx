<script setup lang="ts">
import { onMounted, ref } from "vue";
import ExternalCaptcha from "@/components/auth/captcha/ExternalCaptcha.vue";
import { isExternalCaptcha, type ExternalCaptchaChallenge } from "@/lib/auth/externalCaptcha";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import PasswordInput from "@/components/ui/PasswordInput.vue";
import { ArrowLeft, KeyRound, Lock, Loader2, ShieldCheck, ShieldQuestion, Smartphone, User } from "@lucide/vue";
import AppLogo from "@/components/icons/AppLogo.vue";
import { apiUrl } from "@/lib/common/webPath";
import { translateBackendError } from "@/i18n/backend-errors";
import { mfa } from "@/lib/auth/mfa";
import { oidcStartUrl, publicIdentityProviders, takeSsoError, type PublicIdentityProvider } from "@/lib/auth/identityProviders";

const props = withDefaults(
  defineProps<{
    setupMode?: boolean;
  }>(),
  { setupMode: false },
);

const emit = defineEmits<{ authenticated: [result: { mustChangePassword: boolean; mfaSetupRequired?: boolean }] }>();
const { t } = useI18n();

const username = ref("");
const setupToken = ref("");
const password = ref("");
const confirmPassword = ref("");
const captchaCode = ref("");
const captchaRequired = ref(false);
const captchaId = ref("");
const captchaImage = ref("");
const captchaLoading = ref(false);
const externalCaptcha = ref<ExternalCaptchaChallenge | null>(null);
const captchaToken = ref("");
const captchaRenderKey = ref(0);
const error = ref("");
const loading = ref(false);
const mfaChallenge = ref("");
const ssoProviders = ref<PublicIdentityProvider[]>([]);
const ldapProviders = ref<PublicIdentityProvider[]>([]);
const loginSource = ref("local");
const mfaCode = ref("");

// The auth routes report failures as `{"error": "..."}`, so unwrap that before
// translating; anything else is treated as a plain-text message.
async function readAuthError(res: Response): Promise<string> {
  const text = (await res.text()).trim();
  if (!text) return t("auth.loginFailed");
  let message = text;
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed.error === "string") message = parsed.error;
  } catch {
    // not JSON — fall through with the raw body
  }
  return translateBackendError(t, message) || t("auth.loginFailed");
}

/**
 * Fetch a fresh image challenge. Called once on mount and after every failed
 * attempt: the server consumes a challenge on use, so a rejected login leaves
 * the image stale.
 *
 * A 204 means the server does not want a challenge right now (`DBX_WEB_CAPTCHA`
 * is `off`, or `auto` before any failed attempt), so the field is hidden.
 */
async function refreshCaptcha() {
  if (props.setupMode) return;
  captchaLoading.value = true;
  try {
    const name = username.value.trim();
    const query = name ? `?username=${encodeURIComponent(name)}` : "";
    const res = await fetch(apiUrl(`/api/auth/captcha${query}`), { headers: { Accept: "application/json" } });
    if (res.status === 204) {
      externalCaptcha.value = null;
      captchaToken.value = "";
      captchaRequired.value = false;
      captchaId.value = "";
      captchaImage.value = "";
      captchaCode.value = "";
      return;
    }
    if (!res.ok) throw new Error(String(res.status));
    const body = (await res.json()) as { id?: string; image?: string };
    if (isExternalCaptcha(body)) {
      externalCaptcha.value = body;
      captchaToken.value = "";
      captchaRenderKey.value += 1;
      captchaRequired.value = true;
      captchaId.value = "";
      captchaImage.value = "";
      return;
    }
    externalCaptcha.value = null;
    if (body.id && body.image) {
      captchaRequired.value = true;
      captchaId.value = body.id;
      captchaImage.value = body.image;
      captchaCode.value = "";
    }
  } catch (e: any) {
    captchaRequired.value = false;
    captchaId.value = "";
    captchaImage.value = "";
    error.value = e?.message || t("auth.captchaFailed");
  } finally {
    captchaLoading.value = false;
  }
}

async function submit() {
  if (props.setupMode && password.value !== confirmPassword.value) {
    error.value = t("auth.passwordMismatch");
    return;
  }
  if (!props.setupMode && captchaRequired.value && !externalCaptcha.value && !captchaId.value) {
    error.value = t("auth.captchaFailed");
    await refreshCaptcha();
    return;
  }

  loading.value = true;
  error.value = "";
  try {
    const url = apiUrl(props.setupMode ? "/api/auth/setup" : "/api/auth/login");
    const name = username.value.trim();
    const source = !props.setupMode && loginSource.value !== "local" ? { provider: loginSource.value } : {};
    const basePayload = props.setupMode
      ? { setup_token: setupToken.value.trim(), username: name, password: password.value }
      : captchaRequired.value && externalCaptcha.value
        ? { username: name, password: password.value, captcha_token: captchaToken.value }
        : captchaRequired.value
          ? { username: name, password: password.value, captcha_id: captchaId.value, captcha_code: captchaCode.value }
          : { username: name, password: password.value };
    const payload = { ...basePayload, ...source };
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      const body = (await res.json().catch(() => ({}))) as { must_change_password?: boolean; mfa_setup_required?: boolean; mfa_required?: boolean; challenge?: string };
      if (body.mfa_required && body.challenge) {
        mfaChallenge.value = body.challenge;
        mfaCode.value = "";
        return;
      }
      emit("authenticated", { mustChangePassword: body.must_change_password === true, mfaSetupRequired: body.mfa_setup_required === true });
    } else {
      error.value = await readAuthError(res);
      if (!props.setupMode) await refreshCaptcha();
    }
  } catch (e: any) {
    error.value = e?.message || t("auth.connectFailed");
    if (!props.setupMode) await refreshCaptcha();
  } finally {
    loading.value = false;
  }
}

async function submitMfa() {
  loading.value = true;
  error.value = "";
  try {
    const body = await mfa.verifyLogin(mfaChallenge.value, mfaCode.value.trim());
    emit("authenticated", { mustChangePassword: body.must_change_password === true, mfaSetupRequired: body.mfa_setup_required === true });
  } catch (e: any) {
    const code = e?.message ?? "";
    error.value = translateBackendError(t, code) || t("auth.loginFailed");
    mfaCode.value = "";
    if (code === "mfa_challenge_expired") restartLogin(false);
  } finally {
    loading.value = false;
  }
}

function restartLogin(clearError = true) {
  mfaChallenge.value = "";
  mfaCode.value = "";
  password.value = "";
  if (clearError) error.value = "";
  void refreshCaptcha();
}

function startSso(provider: PublicIdentityProvider) {
  window.location.assign(oidcStartUrl(provider.id));
}

onMounted(() => {
  void refreshCaptcha();
  const ssoError = takeSsoError();
  if (ssoError) error.value = t(`sso.errors.${ssoError}`);
  if (!props.setupMode) {
    void publicIdentityProviders().then((providers) => {
      ssoProviders.value = providers.filter((provider) => provider.kind === "oidc");
      ldapProviders.value = providers.filter((provider) => provider.kind === "ldap");
    });
  }
});
</script>

<template>
  <div class="flex items-center justify-center h-screen bg-gradient-to-br from-background via-background to-blue-950/20">
    <div class="w-[360px] space-y-8">
      <div class="flex flex-col items-center gap-4">
        <AppLogo class="w-20 h-20 rounded-2xl shadow-lg shadow-blue-500/20" />
        <div class="text-center">
          <h1 class="text-2xl font-bold tracking-tight">DBX</h1>
          <p class="text-sm text-muted-foreground mt-1">
            {{ setupMode ? t("auth.setupDescription") : t("auth.loginDescription") }}
          </p>
        </div>
      </div>

      <form v-if="mfaChallenge" class="space-y-4" autocomplete="off" data-testid="mfa-login-form" @submit.prevent="submitMfa">
        <div class="flex items-center justify-center gap-2 text-sm text-muted-foreground">
          <Smartphone class="w-4 h-4" />
          <span>{{ t("mfa.loginTitle") }}</span>
        </div>
        <p class="text-center text-xs text-muted-foreground">{{ t("mfa.loginHint") }}</p>
        <div class="relative">
          <ShieldCheck class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input v-model="mfaCode" :placeholder="t('mfa.loginPlaceholder')" class="pl-10 h-11 tracking-[0.3em]" inputmode="text" autocomplete="one-time-code" maxlength="20" autofocus data-testid="mfa-login-code" />
        </div>
        <p v-if="error" class="text-sm text-destructive text-center">{{ error }}</p>
        <Button type="submit" class="w-full h-11 text-sm font-medium" :disabled="loading || mfaCode.trim().length < 6" data-testid="mfa-login-submit">
          <Loader2 v-if="loading" class="w-4 h-4 animate-spin mr-2" />
          {{ loading ? t("auth.processing") : t("mfa.verify") }}
        </Button>
        <Button type="button" variant="ghost" class="w-full gap-2 text-muted-foreground" @click="restartLogin()">
          <ArrowLeft class="w-4 h-4" />
          {{ t("mfa.backToLogin") }}
        </Button>
      </form>

      <form v-else class="space-y-4" @submit.prevent="submit" autocomplete="off">
        <div v-if="setupMode" class="flex items-center justify-center gap-2 text-sm text-muted-foreground">
          <ShieldCheck class="w-4 h-4" />
          <span>{{ t("auth.setupTitle") }}</span>
        </div>
        <div v-if="setupMode" class="space-y-1">
          <div class="relative">
            <KeyRound class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input v-model="setupToken" :placeholder="t('auth.setupToken')" class="pl-10 h-11 font-mono" autocomplete="off" spellcheck="false" data-testid="setup-token-input" />
          </div>
          <p class="text-xs text-muted-foreground">{{ t("auth.setupTokenHint") }}</p>
        </div>
        <select v-if="!setupMode && ldapProviders.length" v-model="loginSource" class="h-11 w-full rounded-md border border-input bg-background px-3 text-sm" :aria-label="t('sso.ldapSource')" data-testid="login-source">
          <option value="local">{{ t("sso.localAccount") }}</option>
          <option v-for="provider in ldapProviders" :key="provider.id" :value="provider.id">{{ provider.name }}</option>
        </select>
        <div class="relative">
          <User class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input v-model="username" :placeholder="setupMode ? t('auth.newUsername') : t('auth.username')" class="pl-10 h-11" autocomplete="username" spellcheck="false" autofocus data-testid="username-input" />
        </div>
        <div class="relative">
          <Lock class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <PasswordInput v-model="password" :placeholder="setupMode ? t('auth.newPassword') : t('auth.enterPassword')" inputClass="pl-10 h-11" :autocomplete="setupMode ? 'new-password' : 'current-password'" />
        </div>
        <div v-if="setupMode" class="relative">
          <Lock class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <PasswordInput v-model="confirmPassword" :placeholder="t('auth.confirmPassword')" inputClass="pl-10 h-11" autocomplete="off" />
        </div>
        <ExternalCaptcha v-if="!setupMode && captchaRequired && externalCaptcha" :key="captchaRenderKey" :challenge="externalCaptcha" @token="captchaToken = $event" @failed="error = t('auth.captchaWidgetFailed')" />
        <div v-else-if="!setupMode && captchaRequired" class="flex items-start gap-2">
          <div class="relative flex-1">
            <ShieldQuestion class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input v-model="captchaCode" :placeholder="t('auth.captchaPlaceholder')" class="pl-10 h-11 uppercase tracking-[0.35em]" maxlength="5" autocomplete="off" data-testid="captcha-input" />
          </div>
          <button
            type="button"
            class="relative h-11 w-[112px] shrink-0 overflow-hidden rounded-md border bg-muted/40 transition-opacity hover:opacity-80 disabled:opacity-60"
            :title="t('auth.captchaRefresh')"
            :aria-label="t('auth.captchaRefresh')"
            data-testid="captcha-refresh"
            :disabled="captchaLoading"
            @click="refreshCaptcha"
          >
            <img v-if="captchaImage" :src="captchaImage" :alt="t('auth.captchaPlaceholder')" class="h-full w-full object-cover" data-testid="captcha-image" />
            <Loader2 v-else class="absolute left-1/2 top-1/2 w-4 h-4 -translate-x-1/2 -translate-y-1/2 animate-spin text-muted-foreground" />
          </button>
        </div>
        <p v-if="error" class="text-sm text-destructive text-center">{{ error }}</p>
        <Button type="submit" class="w-full h-11 text-sm font-medium" :disabled="loading || !username.trim() || !password || (setupMode && (!confirmPassword || !setupToken.trim())) || (!setupMode && captchaRequired && (externalCaptcha ? !captchaToken : !captchaCode))">
          <Loader2 v-if="loading" class="w-4 h-4 animate-spin mr-2" />
          {{ loading ? t("auth.processing") : setupMode ? t("auth.createAdmin") : t("auth.login") }}
        </Button>
      </form>

      <div v-if="!setupMode && !mfaChallenge && ssoProviders.length" class="space-y-2" data-testid="sso-providers">
        <div class="flex items-center gap-2 text-xs text-muted-foreground">
          <span class="h-px flex-1 bg-border" />
          {{ t("sso.or") }}
          <span class="h-px flex-1 bg-border" />
        </div>
        <Button v-for="provider in ssoProviders" :key="provider.id" type="button" variant="outline" class="h-11 w-full" :data-testid="`sso-${provider.id}`" @click="startSso(provider)">
          {{ t("sso.continueWith", { name: provider.name }) }}
        </Button>
      </div>

      <p class="text-center text-xs text-muted-foreground/50">Powered by DBX</p>
    </div>
  </div>
</template>
