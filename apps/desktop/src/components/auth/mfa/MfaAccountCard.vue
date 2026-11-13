<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import PasswordInput from "@/components/ui/PasswordInput.vue";
import { ShieldCheck, ShieldOff } from "@lucide/vue";
import { translateBackendError } from "@/i18n/backend-errors";
import { mfa, type MfaStatus } from "@/lib/auth/mfa";
import MfaSetup from "./MfaSetup.vue";

const props = defineProps<{ username: string }>();
const { t } = useI18n();

type Mode = "idle" | "enroll" | "regenerate" | "disable";

const status = ref<MfaStatus>();
const mode = ref<Mode>("idle");
const code = ref("");
const password = ref("");
const newCodes = ref<string[]>([]);
const busy = ref(false);
const error = ref("");

function errorText(e: unknown): string {
  return translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("mfa.failed");
}

async function refresh() {
  try {
    status.value = await mfa.status();
  } catch (e) {
    error.value = errorText(e);
  }
}

function open(next: Mode) {
  mode.value = next;
  code.value = "";
  password.value = "";
  newCodes.value = [];
  error.value = "";
}

async function run(action: () => Promise<void>) {
  busy.value = true;
  error.value = "";
  try {
    await action();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}

function regenerate() {
  void run(async () => {
    newCodes.value = await mfa.regenerateRecoveryCodes(code.value.trim());
    code.value = "";
    await refresh();
  });
}

function disable() {
  void run(async () => {
    await mfa.disable(password.value, code.value.trim());
    open("idle");
    await refresh();
  });
}

async function enrolled() {
  open("idle");
  await refresh();
}

onMounted(() => {
  void refresh();
});
</script>

<template>
  <div class="space-y-3" data-testid="mfa-account">
    <div class="flex items-start gap-3">
      <ShieldCheck v-if="status?.enabled" class="mt-0.5 h-5 w-5 text-green-600" />
      <ShieldOff v-else class="mt-0.5 h-5 w-5 text-muted-foreground" />
      <div class="min-w-0 flex-1 space-y-1">
        <Label class="text-base">{{ t("mfa.title") }}</Label>
        <p class="text-sm text-muted-foreground" data-testid="mfa-account-status">
          <template v-if="!status">{{ t("auth.processing") }}</template>
          <template v-else-if="status.enabled">{{ t("mfa.statusEnabled", { count: status.recovery_codes_left }) }}</template>
          <template v-else>{{ t("mfa.statusDisabled") }}</template>
        </p>
        <p v-if="status?.required" class="text-xs text-muted-foreground">{{ t("mfa.requiredByAdmin") }}</p>
      </div>
    </div>
    <p v-if="error" class="text-sm text-destructive">{{ error }}</p>

    <MfaSetup v-if="mode === 'enroll'" :username="props.username" @done="enrolled" @cancel="open('idle')" />

    <form v-else-if="mode === 'regenerate'" class="space-y-2 rounded-md border border-border/60 p-3" @submit.prevent="regenerate">
      <template v-if="newCodes.length">
        <p class="text-sm text-muted-foreground">{{ t("mfa.recoveryCodesHint") }}</p>
        <ul class="grid grid-cols-2 gap-1 rounded-md bg-muted/30 p-3 font-mono text-sm" data-testid="mfa-new-codes">
          <li v-for="item in newCodes" :key="item">{{ item }}</li>
        </ul>
        <div class="flex justify-end">
          <Button type="button" size="sm" @click="open('idle')">{{ t("mfa.savedCodes") }}</Button>
        </div>
      </template>
      <template v-else>
        <p class="text-sm text-muted-foreground">{{ t("mfa.regenerateHint") }}</p>
        <Input v-model="code" inputmode="numeric" maxlength="6" :placeholder="t('mfa.codePlaceholder')" class="h-9 tracking-[0.4em]" data-testid="mfa-regenerate-code" />
        <div class="flex justify-end gap-2">
          <Button type="button" variant="ghost" size="sm" @click="open('idle')">{{ t("common.cancel") }}</Button>
          <Button type="submit" size="sm" :disabled="busy || code.trim().length !== 6">{{ t("mfa.regenerate") }}</Button>
        </div>
      </template>
    </form>

    <form v-else-if="mode === 'disable'" class="space-y-2 rounded-md border border-border/60 p-3" data-testid="mfa-disable-form" @submit.prevent="disable">
      <p class="text-sm text-muted-foreground">{{ t("mfa.disableHint") }}</p>
      <PasswordInput v-model="password" :placeholder="t('auth.oldPassword')" inputClass="h-9" autocomplete="current-password" />
      <Input v-model="code" :placeholder="t('mfa.loginPlaceholder')" class="h-9" autocomplete="one-time-code" data-testid="mfa-disable-code" />
      <div class="flex justify-end gap-2">
        <Button type="button" variant="ghost" size="sm" @click="open('idle')">{{ t("common.cancel") }}</Button>
        <Button type="submit" variant="destructive" size="sm" :disabled="busy || !password || code.trim().length < 6">{{ t("mfa.disable") }}</Button>
      </div>
    </form>

    <div v-else-if="status" class="flex flex-wrap gap-2">
      <Button v-if="!status.enabled" size="sm" data-testid="mfa-account-enable" @click="open('enroll')">{{ t("mfa.enableNow") }}</Button>
      <template v-else>
        <Button variant="outline" size="sm" data-testid="mfa-account-regenerate" @click="open('regenerate')">{{ t("mfa.regenerate") }}</Button>
        <Button v-if="!status.required" variant="ghost" size="sm" class="text-destructive hover:text-destructive" data-testid="mfa-account-disable" @click="open('disable')">
          {{ t("mfa.disable") }}
        </Button>
      </template>
    </div>
  </div>
</template>
