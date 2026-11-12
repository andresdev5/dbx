<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import PasswordInput from "@/components/ui/PasswordInput.vue";
import { KeyRound, Loader2, Lock, LogOut } from "@lucide/vue";
import AppLogo from "@/components/icons/AppLogo.vue";
import { apiUrl } from "@/lib/common/webPath";
import { translateBackendError } from "@/i18n/backend-errors";
import { logoutWeb, readAuthErrorCode } from "@/lib/startup/startupAuthentication";

const MIN_PASSWORD_CHARS = 8;

const props = defineProps<{ username?: string }>();
const emit = defineEmits<{ changed: []; loggedOut: [] }>();
const { t } = useI18n();

const currentPassword = ref("");
const newPassword = ref("");
const confirmPassword = ref("");
const error = ref("");
const loading = ref(false);

const tooShort = computed(() => newPassword.value.length > 0 && [...newPassword.value].length < MIN_PASSWORD_CHARS);

async function submit() {
  if (newPassword.value !== confirmPassword.value) {
    error.value = t("auth.passwordMismatch");
    return;
  }
  if (tooShort.value) {
    error.value = t("auth.passwordTooShort", { min: MIN_PASSWORD_CHARS });
    return;
  }
  loading.value = true;
  error.value = "";
  try {
    const res = await fetch(apiUrl("/api/auth/change-password"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ old_password: currentPassword.value, new_password: newPassword.value }),
    });
    if (res.ok) {
      emit("changed");
      return;
    }
    const code = await readAuthErrorCode(res);
    error.value = translateBackendError(t, code) || t("auth.changePasswordFailed");
  } catch (e: any) {
    error.value = e?.message || t("auth.connectFailed");
  } finally {
    loading.value = false;
  }
}

async function logout() {
  try {
    await logoutWeb();
  } finally {
    emit("loggedOut");
  }
}
</script>

<template>
  <div class="flex items-center justify-center h-screen bg-gradient-to-br from-background via-background to-blue-950/20">
    <div class="w-[360px] space-y-8">
      <div class="flex flex-col items-center gap-4">
        <AppLogo class="w-20 h-20 rounded-2xl shadow-lg shadow-blue-500/20" />
        <div class="text-center">
          <h1 class="text-2xl font-bold tracking-tight">{{ t("auth.forceChangeTitle") }}</h1>
          <p class="text-sm text-muted-foreground mt-1">
            {{ props.username ? t("auth.forceChangeDescriptionFor", { username: props.username }) : t("auth.forceChangeDescription") }}
          </p>
        </div>
      </div>

      <form class="space-y-4" @submit.prevent="submit" autocomplete="off">
        <div class="relative">
          <Lock class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <PasswordInput v-model="currentPassword" :placeholder="t('auth.oldPassword')" inputClass="pl-10 h-11" autocomplete="current-password" autofocus data-testid="current-password" />
        </div>
        <div class="relative">
          <KeyRound class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <PasswordInput v-model="newPassword" :placeholder="t('auth.newPassword')" inputClass="pl-10 h-11" autocomplete="new-password" data-testid="new-password" />
        </div>
        <div class="relative">
          <KeyRound class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <PasswordInput v-model="confirmPassword" :placeholder="t('auth.confirmPassword')" inputClass="pl-10 h-11" autocomplete="new-password" data-testid="confirm-password" />
        </div>
        <p class="text-xs text-muted-foreground">{{ t("auth.passwordRequirements", { min: MIN_PASSWORD_CHARS }) }}</p>
        <p v-if="error" class="text-sm text-destructive text-center">{{ error }}</p>
        <Button type="submit" class="w-full h-11 text-sm font-medium" :disabled="loading || !currentPassword || !newPassword || !confirmPassword">
          <Loader2 v-if="loading" class="w-4 h-4 animate-spin mr-2" />
          {{ loading ? t("auth.processing") : t("auth.changePassword") }}
        </Button>
        <Button type="button" variant="ghost" class="w-full gap-2 text-muted-foreground" @click="logout">
          <LogOut class="w-4 h-4" />
          {{ t("auth.logout") }}
        </Button>
      </form>
    </div>
  </div>
</template>
