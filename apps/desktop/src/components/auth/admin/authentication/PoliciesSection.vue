<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { ShieldAlert, ShieldCheck, ShieldOff } from "@lucide/vue";
import { Switch } from "@/components/ui/switch";
import CaptchaProviderSetting from "@/components/auth/captcha/CaptchaProviderSetting.vue";
import WebLoginCaptchaSetting from "@/components/settings/WebLoginCaptchaSetting.vue";
import { userAdmin } from "@/lib/auth/accessAdmin";
import { useAdminConfirm } from "@/lib/auth/adminConfirm";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import AdminSectionHeader from "../shared/AdminSectionHeader.vue";
import AdminStatCard from "../shared/AdminStatCard.vue";
import { useAdminText } from "../shared/adminUi";

const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();
const confirm = useAdminConfirm();

const requiredAll = ref(false);
const loaded = ref(false);
const saving = ref(false);
const error = ref("");

const stats = computed(() => {
  const active = directory.users.value.filter((user) => user.active);
  return {
    enabled: active.filter((user) => user.mfa_enabled).length,
    missing: active.filter((user) => !user.mfa_enabled).length,
    required: active.filter((user) => user.mfa_required).length,
  };
});

async function load() {
  error.value = "";
  try {
    requiredAll.value = await userAdmin.mfaPolicy();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    loaded.value = true;
  }
}

async function changePolicy(next: boolean) {
  if (!(await confirm({ title: next ? t("mfa.confirmRequireAll") : t("mfa.confirmUnrequireAll"), confirmLabel: t("adminConsole.confirm"), destructive: !next }))) return;
  saving.value = true;
  error.value = "";
  try {
    requiredAll.value = await userAdmin.setMfaPolicy(next);
    await directory.refreshUsers();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    saving.value = false;
  }
}

onMounted(() => {
  void load();
});
</script>

<template>
  <section class="space-y-5" data-testid="admin-policies">
    <AdminSectionHeader :title="t('adminConsole.sections.policies')" :description="t('adminConsole.policies.description')" />

    <p v-if="error" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive" data-testid="admin-policies-error">{{ error }}</p>

    <div class="space-y-4 rounded-lg border border-border/70 p-4" data-testid="admin-policies-mfa">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="max-w-2xl space-y-1">
          <h3 class="text-sm font-semibold">{{ t("adminConsole.policies.mfa.title") }}</h3>
          <p class="text-sm text-muted-foreground">{{ t("adminConsole.policies.mfa.description") }}</p>
        </div>
        <label class="flex items-center gap-3 text-sm font-medium">
          {{ t("mfa.requireAll") }}
          <Switch :model-value="requiredAll" :disabled="!loaded || saving" data-testid="mfa-required-all" @update:model-value="(value: boolean) => changePolicy(value)" />
        </label>
      </div>
      <div class="grid gap-3 sm:grid-cols-3">
        <AdminStatCard :label="t('adminConsole.policies.mfa.enabled')" :value="stats.enabled" :icon="ShieldCheck" tone="success" />
        <AdminStatCard :label="t('adminConsole.policies.mfa.missing')" :value="stats.missing" :icon="ShieldOff" :tone="stats.missing ? 'warning' : 'default'" />
        <AdminStatCard :label="t('adminConsole.policies.mfa.required')" :value="stats.required" :icon="ShieldAlert" />
      </div>
      <p class="text-xs text-muted-foreground">{{ t("adminConsole.policies.mfa.perUserHint") }}</p>
    </div>

    <div class="grid gap-4 lg:grid-cols-2">
      <div class="rounded-lg border border-border/70 p-4">
        <WebLoginCaptchaSetting />
      </div>
      <div class="rounded-lg border border-border/70 p-4">
        <CaptchaProviderSetting />
      </div>
    </div>
  </section>
</template>
