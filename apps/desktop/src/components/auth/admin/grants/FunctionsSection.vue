<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Pencil, SquareFunction } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { accessAdmin, type ConnectionPolicy, type ConnectionSummary } from "@/lib/auth/accessAdmin";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { textMatches, useTableState } from "@/lib/auth/adminTable";
import AdminBadge from "../shared/AdminBadge.vue";
import AdminDataTable, { type AdminColumn } from "../shared/AdminDataTable.vue";
import AdminPagination from "../shared/AdminPagination.vue";
import AdminSearchInput from "../shared/AdminSearchInput.vue";
import AdminSectionHeader from "../shared/AdminSectionHeader.vue";
import AdminStatCard from "../shared/AdminStatCard.vue";
import { useAdminText } from "../shared/adminUi";
import FunctionPolicyDialog from "./FunctionPolicyDialog.vue";

const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();

const policies = ref<ConnectionPolicy[]>([]);
const loading = ref(true);
const error = ref("");
const saved = ref("");
const dialogOpen = ref(false);
const editing = ref<ConnectionSummary | null>(null);

const policyByConnection = computed(() => new Map(policies.value.map((policy) => [policy.connection_id, policy])));
const strictCount = computed(() => policies.value.filter((policy) => policy.strict_function_mode).length);

function policyFor(connectionId: string): ConnectionPolicy | null {
  return policyByConnection.value.get(connectionId) ?? null;
}

const table = useTableState(directory.connections, {
  matches: (connection, query) => textMatches(query, connection.name),
  sorters: {
    connection: (connection) => connection.name.toLocaleLowerCase(),
    mode: (connection) => (policyFor(connection.id)?.strict_function_mode ? 0 : 1),
    allowlist: (connection) => policyFor(connection.id)?.function_allowlist.length ?? 0,
  },
  initialSort: { key: "connection", direction: "asc" },
});

const columns = computed<AdminColumn[]>(() => [
  { key: "connection", label: t("adminConsole.functions.columns.connection"), sortable: true },
  { key: "mode", label: t("adminConsole.functions.columns.mode"), sortable: true },
  { key: "allowlist", label: t("adminConsole.functions.columns.allowlist"), sortable: true },
  { key: "actions", label: "", align: "right", class: "w-10" },
]);

function edit(connection: ConnectionSummary) {
  saved.value = "";
  editing.value = connection;
  dialogOpen.value = true;
}

function onSaved(policy: ConnectionPolicy) {
  policies.value = [...policies.value.filter((candidate) => candidate.connection_id !== policy.connection_id), policy];
  saved.value = policy.connection_id;
}

onMounted(async () => {
  try {
    policies.value = await accessAdmin.policies();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <section class="space-y-5" data-testid="access-functions">
    <AdminSectionHeader :title="t('adminConsole.sections.functions')" :description="t('adminConsole.functions.description')" />

    <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <AdminStatCard :label="t('access.strictMode')" :value="strictCount" :icon="SquareFunction" data-testid="functions-strict-count" />
    </div>

    <p v-if="error" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">{{ error }}</p>

    <AdminSearchInput v-model="table.query.value" :placeholder="t('adminConsole.functions.search')" />

    <AdminDataTable
      :columns="columns"
      :rows="table.paged.value"
      :row-key="(connection) => connection.id"
      :loading="loading || !directory.loaded.value"
      :empty-text="t('adminConsole.functions.empty')"
      :sort-key="table.sortKey.value"
      :sort-direction="table.sortDirection.value"
      clickable
      test-id="functions-connection"
      @sort="table.toggleSort"
      @row-click="edit"
    >
      <template #cell-connection="{ row }">
        <span class="font-medium">{{ row.name }}</span>
        <span v-if="saved === row.id" class="ml-2 text-xs text-emerald-600" data-testid="functions-saved">{{ t("access.saved") }}</span>
      </template>
      <template #cell-mode="{ row }">
        <AdminBadge :tone="policyFor(row.id)?.strict_function_mode ? 'warning' : 'neutral'" data-testid="functions-mode">
          {{ policyFor(row.id)?.strict_function_mode ? t("adminConsole.functions.strict") : t("adminConsole.functions.standard") }}
        </AdminBadge>
      </template>
      <template #cell-allowlist="{ row }">
        <span class="text-sm text-muted-foreground" :title="(policyFor(row.id)?.function_allowlist ?? []).join(', ')" data-testid="functions-count">{{ t("adminConsole.functions.functionsCount", { count: policyFor(row.id)?.function_allowlist.length ?? 0 }) }}</span>
      </template>
      <template #cell-actions="{ row }">
        <Button variant="ghost" size="icon-sm" :aria-label="t('adminConsole.functions.edit')" :title="t('adminConsole.functions.edit')" data-testid="functions-edit" @click="edit(row)">
          <Pencil />
        </Button>
      </template>
      <template #footer>
        <AdminPagination v-model:page="table.page.value" v-model:page-size="table.pageSize.value" :page-count="table.pageCount.value" :total="table.total.value" />
      </template>
    </AdminDataTable>

    <FunctionPolicyDialog v-model:open="dialogOpen" :connection="editing" :policy="editing ? policyFor(editing.id) : null" @saved="onSaved" />
  </section>
</template>
