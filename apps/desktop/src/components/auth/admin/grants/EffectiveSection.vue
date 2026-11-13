<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Eye, EyeOff, Loader2, ShieldCheck } from "@lucide/vue";
import { accessAdmin, describeResource, type EffectivePermissions, type EffectiveRule } from "@/lib/auth/accessAdmin";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { useAdminNavigator } from "@/lib/auth/adminNavigation";
import AdminBadge from "../shared/AdminBadge.vue";
import AdminDataTable, { type AdminColumn } from "../shared/AdminDataTable.vue";
import AdminSectionHeader from "../shared/AdminSectionHeader.vue";
import { fieldLabelClass, selectClass, useAdminText } from "../shared/adminUi";

const props = defineProps<{ userId?: string; embedded?: boolean }>();
const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();
const navigator = useAdminNavigator();

const selectedUser = ref(props.userId ?? "");
const connectionId = ref("");
const result = ref<EffectivePermissions | null>(null);
const loading = ref(false);
const error = ref("");
let requestId = 0;

const columns = computed<AdminColumn[]>(() => [
  { key: "effect", label: t("adminConsole.effective.columns.effect"), class: "w-24" },
  { key: "resource", label: t("adminConsole.effective.columns.resource") },
  { key: "operations", label: t("adminConsole.effective.columns.operations") },
  { key: "source", label: t("adminConsole.effective.columns.source") },
]);

watch(
  () => props.userId,
  (id) => {
    if (id) selectedUser.value = id;
  },
);

watch(
  [selectedUser, connectionId],
  async ([user, connection]) => {
    result.value = null;
    error.value = "";
    if (!user || !connection) return;
    const current = ++requestId;
    loading.value = true;
    try {
      const loaded = await accessAdmin.effective(user, connection);
      if (current === requestId) result.value = loaded;
    } catch (e) {
      if (current === requestId) error.value = errorText(e);
    } finally {
      if (current === requestId) loading.value = false;
    }
  },
  { immediate: true },
);

function ruleKey(rule: EffectiveRule): string {
  return `${rule.grant_id}:${rule.via_group ?? ""}:${rule.effect}`;
}
</script>

<template>
  <section class="space-y-4" data-testid="access-effective">
    <AdminSectionHeader v-if="!embedded" :title="t('adminConsole.sections.effective')" :description="t('adminConsole.effective.description')" />
    <p v-else class="text-sm text-muted-foreground">{{ t("adminConsole.effective.description") }}</p>

    <div class="grid gap-3 sm:grid-cols-2">
      <label v-if="!userId" :class="['block', fieldLabelClass]">
        {{ t("adminConsole.effective.user") }}
        <select v-model="selectedUser" :class="selectClass" data-testid="effective-user">
          <option value="" disabled>{{ t("access.chooseUser") }}</option>
          <option v-for="user in directory.users.value" :key="user.id" :value="user.id">{{ user.display_name || user.username }} ({{ user.username }})</option>
        </select>
      </label>
      <label :class="['block', fieldLabelClass]">
        {{ t("adminConsole.effective.connection") }}
        <select v-model="connectionId" :class="selectClass" data-testid="effective-connection">
          <option value="" disabled>{{ t("access.chooseConnection") }}</option>
          <option v-for="connection in directory.connections.value" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
        </select>
      </label>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">{{ error }}</p>

    <div v-if="loading" class="flex items-center gap-2 text-sm text-muted-foreground">
      <Loader2 class="h-4 w-4 animate-spin" />
      {{ t("adminConsole.loading") }}
    </div>
    <div v-else-if="!result" class="rounded-lg border border-dashed border-border px-4 py-8 text-center text-sm text-muted-foreground">
      {{ userId ? t("adminConsole.effective.pickConnection") : t("adminConsole.effective.pickBoth") }}
    </div>
    <div v-else class="space-y-4" data-testid="effective-result">
      <div class="grid gap-3 lg:grid-cols-2">
        <div class="flex items-start gap-3 rounded-lg border border-border/70 p-4">
          <span :class="['flex h-9 w-9 shrink-0 items-center justify-center rounded-md', result.visible ? 'bg-emerald-500/12 text-emerald-600 dark:text-emerald-400' : 'bg-destructive/10 text-destructive']">
            <Eye v-if="result.visible" class="h-4 w-4" />
            <EyeOff v-else class="h-4 w-4" />
          </span>
          <div class="min-w-0 space-y-1">
            <p class="text-xs text-muted-foreground">{{ t("adminConsole.effective.access") }}</p>
            <p :class="['text-sm font-medium', result.visible ? 'text-emerald-700 dark:text-emerald-400' : 'text-destructive']" data-testid="effective-visibility">{{ result.visible ? t("access.visible") : t("access.hidden") }}</p>
            <AdminBadge v-if="result.implicit_admin" tone="primary">
              <ShieldCheck class="h-3 w-3" />
              {{ t("access.implicitAdmin") }}
            </AdminBadge>
          </div>
        </div>
        <div class="space-y-2 rounded-lg border border-border/70 p-4">
          <p class="text-xs text-muted-foreground">{{ t("access.connectionOperations") }}</p>
          <div class="flex flex-wrap gap-1" data-testid="effective-operations">
            <template v-if="result.connection_operations.length">
              <AdminBadge v-for="operation in result.connection_operations" :key="operation" mono tone="success">{{ operation }}</AdminBadge>
            </template>
            <span v-else class="text-sm text-muted-foreground">{{ t("access.none") }}</span>
          </div>
        </div>
      </div>

      <div class="space-y-2">
        <h3 class="text-sm font-semibold">{{ t("access.rules") }}</h3>
        <AdminDataTable :columns="columns" :rows="result.rules" :row-key="ruleKey" :empty-text="t('access.noRules')" test-id="effective-rule">
          <template #cell-effect="{ row }">
            <AdminBadge :tone="row.effect === 'deny' ? 'danger' : 'success'" dot>{{ row.effect === "deny" ? t("access.deny") : t("access.allow") }}</AdminBadge>
          </template>
          <template #cell-resource="{ row }">
            <span class="font-mono text-xs">{{ describeResource(row.resource, directory.connections.value) }}</span>
          </template>
          <template #cell-operations="{ row }">
            <span class="font-mono text-xs">{{ row.operations.join(" · ") }}</span>
          </template>
          <template #cell-source="{ row }">
            <button v-if="row.via_group" type="button" class="text-left text-sm hover:underline" data-testid="effective-via-group" @click="navigator.go({ section: 'group', id: row.via_group })">
              {{ t("access.viaGroup", { name: directory.groupLabel(row.via_group) }) }}
            </button>
            <span v-else class="text-sm text-muted-foreground">{{ t("adminConsole.effective.direct") }}</span>
          </template>
        </AdminDataTable>
      </div>
    </div>
  </section>
</template>
