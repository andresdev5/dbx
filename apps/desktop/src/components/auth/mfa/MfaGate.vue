<script setup lang="ts">
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { LogOut, ShieldCheck } from "@lucide/vue";
import AppLogo from "@/components/icons/AppLogo.vue";
import MfaSetup from "./MfaSetup.vue";
import { logoutWeb } from "@/lib/startup/startupAuthentication";

const props = defineProps<{ username: string; forced: boolean }>();
const emit = defineEmits<{ done: []; skip: []; loggedOut: [] }>();
const { t } = useI18n();

const enrolling = ref(props.forced);

async function logout() {
  try {
    await logoutWeb();
  } finally {
    emit("loggedOut");
  }
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-gradient-to-br from-background via-background to-blue-950/20 px-4 py-8" data-testid="mfa-gate">
    <div class="w-full max-w-[440px] space-y-6">
      <div class="flex flex-col items-center gap-4">
        <AppLogo class="h-16 w-16 rounded-2xl shadow-lg shadow-blue-500/20" />
        <div class="text-center">
          <h1 class="text-xl font-bold tracking-tight">{{ forced ? t("mfa.requiredTitle") : t("mfa.recommendTitle") }}</h1>
          <p class="mt-1 text-sm text-muted-foreground">
            {{ forced ? t("mfa.requiredDescription", { username: props.username }) : t("mfa.recommendDescription") }}
          </p>
        </div>
      </div>

      <MfaSetup v-if="enrolling" :username="props.username" @done="emit('done')" @cancel="forced ? logout() : (enrolling = false)" />
      <div v-else class="space-y-2">
        <Button class="h-11 w-full gap-2" data-testid="mfa-gate-enable" @click="enrolling = true">
          <ShieldCheck class="h-4 w-4" />
          {{ t("mfa.enableNow") }}
        </Button>
        <Button variant="ghost" class="w-full text-muted-foreground" data-testid="mfa-gate-skip" @click="emit('skip')">{{ t("mfa.later") }}</Button>
      </div>

      <Button v-if="forced" variant="ghost" class="w-full gap-2 text-muted-foreground" @click="logout">
        <LogOut class="h-4 w-4" />
        {{ t("auth.logout") }}
      </Button>
    </div>
  </div>
</template>
