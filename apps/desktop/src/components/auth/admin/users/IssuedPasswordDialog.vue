<script setup lang="ts">
import { ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Check, Copy, KeyRound } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { IssuedPassword } from "./useUserActions";

const props = defineProps<{ issued: IssuedPassword | null }>();
const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();
const copied = ref(false);

watch(
  () => props.issued,
  () => {
    copied.value = false;
  },
);

async function copy() {
  if (!props.issued) return;
  try {
    await navigator.clipboard.writeText(props.issued.password);
    copied.value = true;
  } catch {
    copied.value = false;
  }
}
</script>

<template>
  <Dialog :open="issued !== null" @update:open="(open: boolean) => !open && emit('close')">
    <DialogContent class="sm:max-w-md" data-testid="issued-password">
      <DialogHeader>
        <DialogTitle class="flex items-center gap-2">
          <KeyRound class="h-5 w-5 text-amber-500" />
          {{ t("adminConsole.users.issued.title") }}
        </DialogTitle>
        <DialogDescription class="text-sm text-muted-foreground">{{ t("adminConsole.users.issued.description", { username: issued?.username ?? "" }) }}</DialogDescription>
      </DialogHeader>
      <div class="flex items-center gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2">
        <code class="min-w-0 flex-1 truncate px-1 font-mono text-sm" data-testid="issued-password-value">{{ issued?.password }}</code>
        <Button variant="outline" size="sm" @click="copy">
          <Check v-if="copied" />
          <Copy v-else />
          {{ copied ? t("users.copied") : t("users.copy") }}
        </Button>
      </div>
      <DialogFooter>
        <Button @click="emit('close')">{{ t("adminConsole.users.issued.done") }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
