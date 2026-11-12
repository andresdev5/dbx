<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { translateBackendError } from "@/i18n/backend-errors";
import { accessAdmin, type ConnectionPolicy, type ConnectionSummary } from "@/lib/auth/accessAdmin";

defineProps<{ connections: ConnectionSummary[] }>();
const { t } = useI18n();

const policies = ref<ConnectionPolicy[]>([]);
const connectionId = ref("");
const strict = ref(false);
const allowlist = ref("");
const busy = ref(false);
const error = ref("");
const saved = ref(false);

const selectClass = "h-9 w-full rounded-md border border-input bg-background px-2 text-sm";

function errorText(e: unknown): string {
  return translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("users.actionFailed");
}

function parseAllowlist(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((name) => name.trim())
    .filter(Boolean);
}

function strictConnections(): number {
  return policies.value.filter((policy) => policy.strict_function_mode).length;
}

watch(connectionId, (id) => {
  const policy = policies.value.find((candidate) => candidate.connection_id === id);
  strict.value = policy?.strict_function_mode ?? false;
  allowlist.value = (policy?.function_allowlist ?? []).join("\n");
  saved.value = false;
  error.value = "";
});

async function save() {
  busy.value = true;
  error.value = "";
  saved.value = false;
  try {
    const policy = await accessAdmin.savePolicy({ connection_id: connectionId.value, strict_function_mode: strict.value, function_allowlist: parseAllowlist(allowlist.value) });
    policies.value = [...policies.value.filter((candidate) => candidate.connection_id !== policy.connection_id), policy];
    allowlist.value = policy.function_allowlist.join("\n");
    saved.value = true;
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}

onMounted(async () => {
  try {
    policies.value = await accessAdmin.policies();
  } catch (e) {
    error.value = errorText(e);
  }
});
</script>

<template>
  <div class="space-y-3" data-testid="access-functions">
    <p class="text-sm text-muted-foreground">{{ t("access.functionsDescription") }}</p>
    <p class="text-xs text-muted-foreground">{{ t("access.strictCount", { count: strictConnections() }) }}</p>
    <select v-model="connectionId" :class="selectClass" :aria-label="t('access.connection')" data-testid="functions-connection">
      <option value="" disabled>{{ t("access.chooseConnection") }}</option>
      <option v-for="connection in connections" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
    </select>
    <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
    <form v-if="connectionId" class="space-y-3 rounded-md border border-border/60 p-3" @submit.prevent="save">
      <label class="flex items-center gap-2 text-sm">
        <input v-model="strict" type="checkbox" data-testid="functions-strict" />
        {{ t("access.strictMode") }}
      </label>
      <p class="text-xs text-muted-foreground">{{ t("access.strictModeHint") }}</p>
      <label class="block space-y-1 text-xs text-muted-foreground">
        {{ t("access.allowlist") }}
        <textarea v-model="allowlist" rows="5" class="w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs text-foreground" :placeholder="t('access.allowlistPlaceholder')" data-testid="functions-allowlist" />
      </label>
      <div class="flex items-center justify-end gap-3">
        <span v-if="saved" class="text-xs text-green-600">{{ t("access.saved") }}</span>
        <Button type="submit" size="sm" :disabled="busy" data-testid="functions-save">{{ t("access.save") }}</Button>
      </div>
    </form>
  </div>
</template>
