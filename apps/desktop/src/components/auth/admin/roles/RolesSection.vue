<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Copy, Pencil, Plus, RefreshCw, Trash2 } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { accessAdmin, type DataRole, type Grant } from "@/lib/auth/accessAdmin";
import { useAdminConfirm } from "@/lib/auth/adminConfirm";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { textMatches, useTableState } from "@/lib/auth/adminTable";
import AdminBadge from "../shared/AdminBadge.vue";
import AdminDataTable, { type AdminColumn } from "../shared/AdminDataTable.vue";
import AdminPagination from "../shared/AdminPagination.vue";
import AdminRowMenu, { type AdminRowAction } from "../shared/AdminRowMenu.vue";
import AdminSearchInput from "../shared/AdminSearchInput.vue";
import AdminSectionHeader from "../shared/AdminSectionHeader.vue";
import { selectClass, useAdminText } from "../shared/adminUi";
import RoleFormDialog, { type RoleDraftSource } from "./RoleFormDialog.vue";

const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();
const confirm = useAdminConfirm();

const grants = ref<Grant[]>([]);
const kindFilter = ref<"" | "builtin" | "custom">("");
const formOpen = ref(false);
const formSource = ref<RoleDraftSource>({ role: null });
const refreshing = ref(false);
const busyId = ref("");
const error = ref("");

const usage = computed(() => {
  const counts = new Map<string, number>();
  for (const grant of grants.value) {
    if (grant.role_id) counts.set(grant.role_id, (counts.get(grant.role_id) ?? 0) + 1);
  }
  return counts;
});

function roleLabel(role: DataRole): string {
  return role.builtin ? t(`access.builtinRoles.${role.name}`) : role.name;
}

const table = useTableState(directory.roles, {
  matches: (role, query) => textMatches(query, roleLabel(role), role.name, role.description, role.operations.join(" ")),
  filter: (role) => {
    if (kindFilter.value === "builtin") return role.builtin;
    if (kindFilter.value === "custom") return !role.builtin;
    return true;
  },
  sorters: {
    role: (role) => roleLabel(role).toLocaleLowerCase(),
    operations: (role) => role.operations.length,
    usage: (role) => usage.value.get(role.id) ?? 0,
  },
});

const columns = computed<AdminColumn[]>(() => [
  { key: "role", label: t("adminConsole.roles.columns.role"), sortable: true },
  { key: "operations", label: t("adminConsole.roles.columns.operations"), sortable: true },
  { key: "usage", label: t("adminConsole.roles.columns.usage"), sortable: true, class: "whitespace-nowrap" },
  { key: "actions", label: "", align: "right", class: "w-10" },
]);

const hasFilters = computed(() => Boolean(table.query.value || kindFilter.value));

async function loadGrants() {
  try {
    grants.value = await accessAdmin.grants();
  } catch (e) {
    error.value = errorText(e);
  }
}

async function refresh() {
  refreshing.value = true;
  error.value = "";
  await Promise.all([directory.refreshRoles(), loadGrants()]);
  refreshing.value = false;
}

function openForm(role: DataRole | null, duplicate = false) {
  formSource.value = { role, duplicate };
  formOpen.value = true;
}

async function remove(role: DataRole) {
  const used = usage.value.get(role.id) ?? 0;
  const description = used ? `${t("adminConsole.roles.confirm.deleteDescription")} ${t("adminConsole.roles.confirm.deleteInUse", { count: used })}` : t("adminConsole.roles.confirm.deleteDescription");
  if (!(await confirm({ title: t("adminConsole.roles.confirm.deleteTitle", { name: roleLabel(role) }), description, confirmLabel: t("adminConsole.roles.actions.delete"), destructive: true }))) return;
  busyId.value = role.id;
  error.value = "";
  try {
    await accessAdmin.deleteRole(role.id);
    await Promise.all([directory.refreshRoles(), loadGrants()]);
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busyId.value = "";
  }
}

function actionsFor(role: DataRole): AdminRowAction[] {
  if (role.builtin) return [{ key: "duplicate", label: t("adminConsole.roles.actions.duplicate"), icon: Copy, action: () => openForm(role, true) }];
  return [
    { key: "edit", label: t("adminConsole.roles.actions.edit"), icon: Pencil, action: () => openForm(role) },
    { key: "duplicate", label: t("adminConsole.roles.actions.duplicate"), icon: Copy, action: () => openForm(role, true) },
    { key: "separator-danger", separator: true },
    { key: "delete", label: t("adminConsole.roles.actions.delete"), icon: Trash2, destructive: true, action: () => void remove(role) },
  ];
}

function clearFilters() {
  table.query.value = "";
  kindFilter.value = "";
}

onMounted(() => {
  void loadGrants();
});
</script>

<template>
  <section class="space-y-5" data-testid="admin-roles">
    <AdminSectionHeader :title="t('adminConsole.sections.roles')" :description="t('adminConsole.roles.description')">
      <template #actions>
        <Button variant="outline" size="sm" :disabled="refreshing" @click="refresh">
          <RefreshCw :class="refreshing ? 'animate-spin' : ''" />
          {{ t("adminConsole.refresh") }}
        </Button>
        <Button size="sm" data-testid="admin-roles-new" @click="openForm(null)">
          <Plus />
          {{ t("adminConsole.roles.newRole") }}
        </Button>
      </template>
    </AdminSectionHeader>

    <p v-if="error" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive" data-testid="admin-roles-error">{{ error }}</p>

    <div class="flex flex-wrap items-center gap-2">
      <AdminSearchInput v-model="table.query.value" :placeholder="t('adminConsole.roles.search')" />
      <select v-model="kindFilter" :class="[selectClass, 'w-auto']" :aria-label="t('adminConsole.roles.filters.kind')" data-testid="admin-roles-kind-filter">
        <option value="">{{ t("adminConsole.roles.filters.anyKind") }}</option>
        <option value="builtin">{{ t("adminConsole.roles.filters.builtin") }}</option>
        <option value="custom">{{ t("adminConsole.roles.filters.custom") }}</option>
      </select>
      <Button v-if="hasFilters" variant="ghost" size="sm" @click="clearFilters">{{ t("audit.clear") }}</Button>
    </div>

    <AdminDataTable
      :columns="columns"
      :rows="table.paged.value"
      :row-key="(role) => role.id"
      :loading="!directory.loaded.value"
      :empty-text="t('adminConsole.roles.empty')"
      :empty-hint="hasFilters ? t('adminConsole.roles.emptyHint') : ''"
      :sort-key="table.sortKey.value"
      :sort-direction="table.sortDirection.value"
      test-id="admin-roles-table"
      @sort="table.toggleSort"
    >
      <template #cell-role="{ row }">
        <div class="min-w-0">
          <p class="flex items-center gap-1.5 font-medium">
            <span class="truncate">{{ roleLabel(row) }}</span>
            <AdminBadge :tone="row.builtin ? 'info' : 'neutral'" data-testid="role-kind">{{ row.builtin ? t("adminConsole.roles.builtin") : t("adminConsole.roles.custom") }}</AdminBadge>
          </p>
          <p v-if="row.description" class="truncate text-xs text-muted-foreground">{{ row.description }}</p>
        </div>
      </template>
      <template #cell-operations="{ row }">
        <div class="flex max-w-xl flex-wrap gap-1">
          <AdminBadge v-for="operation in row.operations" :key="operation" :tone="operation === 'UNCLASSIFIED' ? 'warning' : 'neutral'" mono>{{ operation }}</AdminBadge>
        </div>
      </template>
      <template #cell-usage="{ row }">
        <span v-if="usage.get(row.id)" class="text-sm">{{ t("adminConsole.roles.usageCount", { count: usage.get(row.id) }) }}</span>
        <span v-else class="text-xs text-muted-foreground">{{ t("adminConsole.roles.unused") }}</span>
      </template>
      <template #cell-actions="{ row }">
        <AdminRowMenu :actions="actionsFor(row)" :disabled="busyId === row.id" />
      </template>
      <template #footer>
        <AdminPagination v-model:page="table.page.value" v-model:page-size="table.pageSize.value" :page-count="table.pageCount.value" :total="table.total.value" />
      </template>
    </AdminDataTable>

    <RoleFormDialog v-model:open="formOpen" :source="formSource" @saved="loadGrants" />
  </section>
</template>
