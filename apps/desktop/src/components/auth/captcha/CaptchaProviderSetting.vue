<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { translateBackendError } from "@/i18n/backend-errors";
import { apiUrl } from "@/lib/common/webPath";
import { readAuthErrorCode } from "@/lib/startup/startupAuthentication";

type Provider = "builtin" | "cap" | "turnstile" | "hcaptcha" | "recaptcha";

interface CaptchaSettings {
  provider: Provider;
  site_key: string;
  endpoint: string;
  has_secret: boolean;
  provider_env_locked: boolean;
  fallback_active: boolean;
}

const { t } = useI18n();
const PROVIDERS: Provider[] = ["builtin", "cap", "turnstile", "hcaptcha", "recaptcha"];

const settings = ref<CaptchaSettings>();
const provider = ref<Provider>("builtin");
const siteKey = ref("");
const endpoint = ref("");
const secret = ref("");
const saving = ref(false);
const message = ref("");
const messageIsError = ref(false);

const external = computed(() => provider.value !== "builtin");
const locked = computed(() => settings.value?.provider_env_locked === true);

async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(apiUrl(`/api/admin/security/${path}`), {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(await readAuthErrorCode(response));
  return (await response.json()) as T;
}

function apply(loaded: CaptchaSettings) {
  settings.value = loaded;
  provider.value = loaded.provider;
  siteKey.value = loaded.site_key;
  endpoint.value = loaded.endpoint;
  secret.value = "";
}

async function load() {
  try {
    apply(await post<CaptchaSettings>("captcha", {}));
  } catch (e) {
    messageIsError.value = true;
    message.value = translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("captchaProvider.saveFailed");
  }
}

async function save() {
  saving.value = true;
  message.value = "";
  try {
    const body: Record<string, unknown> = { provider: provider.value, site_key: siteKey.value, endpoint: endpoint.value };
    if (secret.value.trim()) body.secret = secret.value.trim();
    apply(await post<CaptchaSettings>("captcha/save", body));
    messageIsError.value = false;
    message.value = t("captchaProvider.saved");
  } catch (e) {
    messageIsError.value = true;
    message.value = translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("captchaProvider.saveFailed");
  } finally {
    saving.value = false;
  }
}

onMounted(() => {
  void load();
});
</script>

<template>
  <form class="space-y-3" data-testid="captcha-provider" @submit.prevent="save">
    <div class="space-y-1">
      <Label class="text-base">{{ t("captchaProvider.title") }}</Label>
      <p class="text-sm text-muted-foreground">{{ t("captchaProvider.description") }}</p>
    </div>
    <p v-if="locked" class="text-xs text-muted-foreground" data-testid="captcha-provider-locked">{{ t("captchaProvider.envLocked") }}</p>
    <p v-if="settings?.fallback_active" class="text-xs text-amber-600" data-testid="captcha-provider-fallback">{{ t("captchaProvider.fallbackActive") }}</p>
    <select v-model="provider" class="h-9 w-full rounded-md border border-input bg-background px-2 text-sm" :disabled="locked" :aria-label="t('captchaProvider.provider')" data-testid="captcha-provider-select">
      <option v-for="item in PROVIDERS" :key="item" :value="item">{{ t(`captchaProvider.providers.${item}`) }}</option>
    </select>
    <template v-if="external">
      <Input v-if="provider === 'cap'" v-model="endpoint" :placeholder="t('captchaProvider.endpoint')" class="h-9" :disabled="locked" data-testid="captcha-provider-endpoint" />
      <Input v-model="siteKey" :placeholder="t('captchaProvider.siteKey')" class="h-9" :disabled="locked" data-testid="captcha-provider-site-key" />
      <Input v-model="secret" type="password" autocomplete="off" :placeholder="settings?.has_secret ? t('captchaProvider.secretKept') : t('captchaProvider.secret')" class="h-9" :disabled="locked" data-testid="captcha-provider-secret" />
      <p class="text-xs text-muted-foreground">{{ t("captchaProvider.recoveryHint") }}</p>
    </template>
    <div class="flex items-center justify-end gap-3">
      <span v-if="message" :class="['text-xs', messageIsError ? 'text-destructive' : 'text-green-600']" data-testid="captcha-provider-message">{{ message }}</span>
      <Button type="submit" size="sm" :disabled="saving || locked" data-testid="captcha-provider-save">{{ t("access.save") }}</Button>
    </div>
  </form>
</template>
