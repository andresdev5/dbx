<script setup lang="ts">
import { ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Loader2 } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import { accessAdmin, type ConnectionPolicy, type ConnectionSummary } from "@/lib/auth/accessAdmin";
import { fieldLabelClass, useAdminText } from "../shared/adminUi";

const props = defineProps<{ open: boolean; connection: ConnectionSummary | null; policy: ConnectionPolicy | null }>();
const emit = defineEmits<{ "update:open": [open: boolean]; saved: [policy: ConnectionPolicy] }>();
const { t } = useI18n();
const { errorText } = useAdminText();

const strict = ref(false);
const allowlist = ref("");
const busy = ref(false);
const error = ref("");

function parseAllowlist(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((name) => name.trim())
    .filter(Boolean);
}

watch(
  () => props.open,
  (open) => {
    if (!open) return;
    strict.value = props.policy?.strict_function_mode ?? false;
    allowlist.value = (props.policy?.function_allowlist ?? []).join("\n");
    error.value = "";
  },
  { immediate: true },
);

async function submit() {
  if (!props.connection) return;
  busy.value = true;
  error.value = "";
  try {
    const saved = await accessAdmin.savePolicy({ connection_id: props.connection.id, strict_function_mode: strict.value, function_allowlist: parseAllowlist(allowlist.value) });
    emit("saved", saved);
    emit("update:open", false);
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <Dialog :open="open" @update:open="(value: boolean) => emit('update:open', value)">
    <DialogContent class="sm:max-w-lg" data-testid="function-policy-dialog">
      <DialogHeader>
        <DialogTitle>{{ t("adminConsole.functions.dialogTitle", { name: connection?.name ?? "" }) }}</DialogTitle>
      </DialogHeader>
      <form id="admin-function-policy-form" class="space-y-4" data-testid="access-functions-form" @submit.prevent="submit">
        <label class="flex items-start justify-between gap-4 rounded-md border border-border/60 p-3">
          <span class="space-y-1">
            <span class="block text-sm font-medium">{{ t("access.strictMode") }}</span>
            <span class="block text-xs text-muted-foreground">{{ t("access.strictModeHint") }}</span>
          </span>
          <Switch v-model="strict" data-testid="functions-strict" />
        </label>
        <label :class="['block', fieldLabelClass]">
          {{ t("access.allowlist") }}
          <textarea
            v-model="allowlist"
            rows="8"
            class="w-full rounded-md border border-input bg-transparent px-2.5 py-1.5 font-mono text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
            :placeholder="t('access.allowlistPlaceholder')"
            data-testid="functions-allowlist"
          />
        </label>
        <p v-if="error" class="text-sm text-destructive" data-testid="functions-error">{{ error }}</p>
      </form>
      <DialogFooter>
        <Button variant="outline" @click="emit('update:open', false)">{{ t("common.cancel") }}</Button>
        <Button type="submit" form="admin-function-policy-form" :disabled="busy || !connection" data-testid="functions-save">
          <Loader2 v-if="busy" class="animate-spin" />
          {{ t("access.save") }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
