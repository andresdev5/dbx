<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Loader2 } from "@lucide/vue";
import { renderExternalCaptcha, type ExternalCaptchaChallenge, type RenderedCaptcha } from "@/lib/auth/externalCaptcha";

const props = defineProps<{ challenge: ExternalCaptchaChallenge }>();
const emit = defineEmits<{ token: [token: string]; failed: [] }>();
const { t } = useI18n();

const container = ref<HTMLElement>();
const loading = ref(true);
let rendered: RenderedCaptcha | undefined;

function reset() {
  emit("token", "");
  rendered?.reset();
}

defineExpose({ reset });

onMounted(async () => {
  if (!container.value) return;
  try {
    rendered = await renderExternalCaptcha(
      container.value,
      props.challenge,
      (token) => emit("token", token),
      () => emit("token", ""),
    );
  } catch {
    emit("failed");
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <div class="flex min-h-[65px] items-center justify-center" data-testid="external-captcha">
    <Loader2 v-if="loading" class="h-4 w-4 animate-spin text-muted-foreground" :aria-label="t('auth.processing')" />
    <div ref="container" />
  </div>
</template>
