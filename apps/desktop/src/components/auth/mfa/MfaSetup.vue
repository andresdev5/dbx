<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Check, Copy, Download, Loader2 } from "@lucide/vue";
import { translateBackendError } from "@/i18n/backend-errors";
import { mfa, qrSvg, recoveryCodesText, type MfaEnrollment } from "@/lib/auth/mfa";
import { downloadText } from "@/lib/auth/auditAdmin";

const props = defineProps<{ username: string }>();
const emit = defineEmits<{ done: []; cancel: [] }>();
const { t } = useI18n();

const enrollment = ref<MfaEnrollment>();
const code = ref("");
const recoveryCodes = ref<string[]>([]);
const loading = ref(false);
const error = ref("");
const copied = ref(false);

const qr = computed(() => (enrollment.value ? qrSvg(enrollment.value.otpauth_uri) : ""));
const formattedSecret = computed(() => enrollment.value?.secret.replace(/(.{4})/g, "$1 ").trim() ?? "");

function errorText(e: unknown): string {
  return translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("mfa.failed");
}

async function start() {
  loading.value = true;
  error.value = "";
  try {
    enrollment.value = await mfa.setup();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    loading.value = false;
  }
}

async function confirm() {
  loading.value = true;
  error.value = "";
  try {
    recoveryCodes.value = await mfa.confirm(code.value.trim());
  } catch (e) {
    error.value = errorText(e);
    code.value = "";
  } finally {
    loading.value = false;
  }
}

async function copyCodes() {
  try {
    await navigator.clipboard.writeText(recoveryCodesText(props.username, recoveryCodes.value));
    copied.value = true;
  } catch {
    copied.value = false;
  }
}

function downloadCodes() {
  downloadText(`dbx-recovery-codes-${props.username}.txt`, recoveryCodesText(props.username, recoveryCodes.value), "text/plain");
}

onMounted(() => {
  void start();
});
</script>

<template>
  <div class="space-y-4" data-testid="mfa-setup">
    <p v-if="error" class="text-sm text-destructive" data-testid="mfa-setup-error">{{ error }}</p>
    <div v-if="loading && !enrollment" class="flex items-center gap-2 text-sm text-muted-foreground">
      <Loader2 class="h-4 w-4 animate-spin" />
      {{ t("auth.processing") }}
    </div>

    <template v-if="recoveryCodes.length">
      <div class="space-y-1">
        <p class="text-sm font-medium">{{ t("mfa.enabledTitle") }}</p>
        <p class="text-sm text-muted-foreground">{{ t("mfa.recoveryCodesHint") }}</p>
      </div>
      <ul class="grid grid-cols-2 gap-1 rounded-md border border-border/60 bg-muted/30 p-3 font-mono text-sm" data-testid="mfa-recovery-codes">
        <li v-for="item in recoveryCodes" :key="item">{{ item }}</li>
      </ul>
      <div class="flex flex-wrap justify-end gap-2">
        <Button type="button" variant="outline" size="sm" @click="copyCodes">
          <Check v-if="copied" class="mr-1 h-4 w-4" />
          <Copy v-else class="mr-1 h-4 w-4" />
          {{ copied ? t("users.copied") : t("users.copy") }}
        </Button>
        <Button type="button" variant="outline" size="sm" @click="downloadCodes">
          <Download class="mr-1 h-4 w-4" />
          {{ t("mfa.download") }}
        </Button>
        <Button type="button" size="sm" data-testid="mfa-setup-done" @click="emit('done')">{{ t("mfa.savedCodes") }}</Button>
      </div>
    </template>

    <form v-else-if="enrollment" class="space-y-3" @submit.prevent="confirm">
      <p class="text-sm text-muted-foreground">{{ t("mfa.scanHint") }}</p>
      <div class="flex flex-col items-center gap-3 sm:flex-row sm:items-start">
        <div class="h-44 w-44 shrink-0 overflow-hidden rounded-md bg-white p-1 [&>svg]:h-full [&>svg]:w-full" data-testid="mfa-qr" v-html="qr" />
        <div class="min-w-0 space-y-1 text-sm">
          <p class="text-muted-foreground">{{ t("mfa.manualKey") }}</p>
          <p class="break-all font-mono" data-testid="mfa-secret">{{ formattedSecret }}</p>
        </div>
      </div>
      <Input v-model="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" :placeholder="t('mfa.codePlaceholder')" class="h-10 tracking-[0.4em]" data-testid="mfa-setup-code" />
      <div class="flex justify-end gap-2">
        <Button type="button" variant="ghost" size="sm" @click="emit('cancel')">{{ t("common.cancel") }}</Button>
        <Button type="submit" size="sm" :disabled="loading || code.trim().length !== 6" data-testid="mfa-setup-confirm">
          <Loader2 v-if="loading" class="mr-1 h-4 w-4 animate-spin" />
          {{ t("mfa.activate") }}
        </Button>
      </div>
    </form>
  </div>
</template>
