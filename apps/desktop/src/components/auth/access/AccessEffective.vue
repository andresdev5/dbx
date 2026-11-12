<script setup lang="ts">
import { ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Loader2 } from "@lucide/vue";
import { translateBackendError } from "@/i18n/backend-errors";
import { accessAdmin, describeResource, type ConnectionSummary, type EffectivePermissions, type ManagedUser, type UserGroup } from "@/lib/auth/accessAdmin";

const props = defineProps<{ users: ManagedUser[]; groups: UserGroup[]; connections: ConnectionSummary[] }>();
const { t } = useI18n();

const userId = ref("");
const connectionId = ref("");
const result = ref<EffectivePermissions | null>(null);
const loading = ref(false);
const error = ref("");
let requestId = 0;

const selectClass = "h-9 w-full rounded-md border border-input bg-background px-2 text-sm";

function groupName(id: string): string {
  return props.groups.find((group) => group.id === id)?.name ?? id;
}

watch([userId, connectionId], async ([user, connection]) => {
  result.value = null;
  error.value = "";
  if (!user || !connection) return;
  const current = ++requestId;
  loading.value = true;
  try {
    const loaded = await accessAdmin.effective(user, connection);
    if (current === requestId) result.value = loaded;
  } catch (e) {
    if (current === requestId) error.value = translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("users.actionFailed");
  } finally {
    if (current === requestId) loading.value = false;
  }
});
</script>

<template>
  <div class="space-y-3" data-testid="access-effective">
    <p class="text-sm text-muted-foreground">{{ t("access.effectiveDescription") }}</p>
    <div class="grid gap-2 sm:grid-cols-2">
      <select v-model="userId" :class="selectClass" :aria-label="t('access.subjectKindUser')" data-testid="effective-user">
        <option value="" disabled>{{ t("access.chooseUser") }}</option>
        <option v-for="user in users" :key="user.id" :value="user.id">{{ user.display_name || user.username }} ({{ user.username }})</option>
      </select>
      <select v-model="connectionId" :class="selectClass" :aria-label="t('access.connection')" data-testid="effective-connection">
        <option value="" disabled>{{ t("access.chooseConnection") }}</option>
        <option v-for="connection in connections" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
      </select>
    </div>
    <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
    <div v-if="loading" class="flex items-center gap-2 text-sm text-muted-foreground">
      <Loader2 class="h-4 w-4 animate-spin" />
      {{ t("auth.processing") }}
    </div>
    <div v-else-if="result" class="space-y-3 rounded-md border border-border/60 p-3" data-testid="effective-result">
      <p class="text-sm">
        <span :class="result.visible ? 'text-green-600' : 'text-destructive'">{{ result.visible ? t("access.visible") : t("access.hidden") }}</span>
        <span v-if="result.implicit_admin" class="text-muted-foreground"> · {{ t("access.implicitAdmin") }}</span>
      </p>
      <div class="space-y-1">
        <p class="text-xs text-muted-foreground">{{ t("access.connectionOperations") }}</p>
        <p class="font-mono text-xs" data-testid="effective-operations">{{ result.connection_operations.length ? result.connection_operations.join(" · ") : t("access.none") }}</p>
      </div>
      <div class="space-y-1">
        <p class="text-xs text-muted-foreground">{{ t("access.rules") }}</p>
        <p v-if="!result.rules.length" class="text-xs text-muted-foreground">{{ t("access.noRules") }}</p>
        <div v-for="rule in result.rules" :key="rule.grant_id" class="flex items-start gap-2 text-xs" data-testid="effective-rule">
          <span :class="['rounded px-1.5 py-0.5 font-medium', rule.effect === 'deny' ? 'bg-destructive/15 text-destructive' : 'bg-green-500/15 text-green-600']">
            {{ rule.effect === "deny" ? t("access.deny") : t("access.allow") }}
          </span>
          <div class="min-w-0 flex-1">
            <p class="truncate">{{ describeResource(rule.resource, connections) }}</p>
            <p class="truncate font-mono text-muted-foreground">{{ rule.operations.join(" · ") }}</p>
            <p v-if="rule.via_group" class="text-muted-foreground">{{ t("access.viaGroup", { name: groupName(rule.via_group) }) }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
