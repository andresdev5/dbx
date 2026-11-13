<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Eye, Pencil, Plus, RefreshCw, Trash2, Users } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { accessAdmin, type Grant, type UserGroup } from "@/lib/auth/accessAdmin";
import { useAdminConfirm } from "@/lib/auth/adminConfirm";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { useAdminNavigator } from "@/lib/auth/adminNavigation";
import { textMatches, useTableState } from "@/lib/auth/adminTable";
import AdminAvatar from "../shared/AdminAvatar.vue";
import AdminBadge from "../shared/AdminBadge.vue";
import AdminDataTable, { type AdminColumn } from "../shared/AdminDataTable.vue";
import AdminPagination from "../shared/AdminPagination.vue";
import AdminRowMenu, { type AdminRowAction } from "../shared/AdminRowMenu.vue";
import AdminSearchInput from "../shared/AdminSearchInput.vue";
import AdminSectionHeader from "../shared/AdminSectionHeader.vue";
import { useAdminText } from "../shared/adminUi";
import GroupFormDialog from "./GroupFormDialog.vue";
import MemberPickerDialog from "./MemberPickerDialog.vue";

const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();
const navigator = useAdminNavigator();
const confirm = useAdminConfirm();

const grants = ref<Grant[]>([]);
const formOpen = ref(false);
const editingGroup = ref<UserGroup | null>(null);
const pickerOpen = ref(false);
const pickerGroup = ref<UserGroup | null>(null);
const refreshing = ref(false);
const busyId = ref("");
const error = ref("");

const grantCounts = computed(() => {
  const counts = new Map<string, number>();
  for (const grant of grants.value) {
    if (grant.subject.kind === "group") counts.set(grant.subject.id, (counts.get(grant.subject.id) ?? 0) + 1);
  }
  return counts;
});

const table = useTableState(directory.groups, {
  matches: (group, query) => textMatches(query, group.name, group.description),
  sorters: {
    group: (group) => group.name.toLocaleLowerCase(),
    members: (group) => group.member_ids.length,
    permissions: (group) => grantCounts.value.get(group.id) ?? 0,
  },
  initialSort: { key: "group", direction: "asc" },
});

const columns = computed<AdminColumn[]>(() => [
  { key: "group", label: t("adminConsole.groups.columns.group"), sortable: true },
  { key: "members", label: t("adminConsole.groups.columns.members"), sortable: true },
  { key: "permissions", label: t("adminConsole.groups.columns.permissions"), sortable: true },
  { key: "actions", label: "", align: "right", class: "w-10" },
]);

function memberPreview(group: UserGroup) {
  return group.member_ids
    .map((id) => directory.users.value.find((user) => user.id === id))
    .filter((user) => user !== undefined)
    .slice(0, 4);
}

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
  await Promise.all([directory.refreshGroups(), directory.refreshUsers(), loadGrants()]);
  refreshing.value = false;
}

function openCreate() {
  editingGroup.value = null;
  formOpen.value = true;
}

function openEdit(group: UserGroup) {
  editingGroup.value = group;
  formOpen.value = true;
}

function openMembers(group: UserGroup) {
  pickerGroup.value = group;
  pickerOpen.value = true;
}

function openDetail(group: UserGroup) {
  navigator.go({ section: "group", id: group.id });
}

function onSaved(group: UserGroup | null) {
  if (group) navigator.go({ section: "group", id: group.id });
}

async function remove(group: UserGroup) {
  if (!(await confirm({ title: t("adminConsole.groups.confirm.deleteTitle", { name: group.name }), description: t("adminConsole.groups.confirm.deleteDescription"), confirmLabel: t("adminConsole.groups.actions.delete"), destructive: true }))) return;
  busyId.value = group.id;
  error.value = "";
  try {
    await accessAdmin.deleteGroup(group.id);
    await Promise.all([directory.refreshGroups(), loadGrants()]);
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busyId.value = "";
  }
}

function actionsFor(group: UserGroup): AdminRowAction[] {
  return [
    { key: "view", label: t("adminConsole.groups.actions.view"), icon: Eye, action: () => openDetail(group) },
    { key: "edit", label: t("adminConsole.groups.actions.edit"), icon: Pencil, action: () => openEdit(group) },
    { key: "members", label: t("adminConsole.groups.actions.members"), icon: Users, action: () => openMembers(group) },
    { key: "separator-danger", separator: true },
    { key: "delete", label: t("adminConsole.groups.actions.delete"), icon: Trash2, destructive: true, action: () => void remove(group) },
  ];
}

onMounted(() => {
  void loadGrants();
});
</script>

<template>
  <section class="space-y-5" data-testid="admin-groups">
    <AdminSectionHeader :title="t('adminConsole.sections.groups')" :description="t('adminConsole.groups.description')">
      <template #actions>
        <Button variant="outline" size="sm" :disabled="refreshing" @click="refresh">
          <RefreshCw :class="refreshing ? 'animate-spin' : ''" />
          {{ t("adminConsole.refresh") }}
        </Button>
        <Button size="sm" data-testid="admin-groups-new" @click="openCreate">
          <Plus />
          {{ t("adminConsole.groups.newGroup") }}
        </Button>
      </template>
    </AdminSectionHeader>

    <p v-if="error" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive" data-testid="admin-groups-error">{{ error }}</p>

    <div class="flex flex-wrap items-center gap-2">
      <AdminSearchInput v-model="table.query.value" :placeholder="t('adminConsole.groups.search')" />
    </div>

    <AdminDataTable
      :columns="columns"
      :rows="table.paged.value"
      :row-key="(group) => group.id"
      :loading="!directory.loaded.value"
      :empty-text="table.query.value ? t('adminConsole.groups.emptySearch') : t('adminConsole.groups.empty')"
      :empty-hint="table.query.value ? '' : t('adminConsole.groups.emptyHint')"
      :sort-key="table.sortKey.value"
      :sort-direction="table.sortDirection.value"
      clickable
      test-id="admin-groups-table"
      @sort="table.toggleSort"
      @row-click="openDetail"
    >
      <template #cell-group="{ row }">
        <div class="min-w-0">
          <p class="truncate font-medium">{{ row.name }}</p>
          <p v-if="row.description" class="truncate text-xs text-muted-foreground">{{ row.description }}</p>
        </div>
      </template>
      <template #cell-members="{ row }">
        <div class="flex items-center gap-2">
          <div v-if="row.member_ids.length" class="flex -space-x-1.5">
            <AdminAvatar v-for="member in memberPreview(row)" :key="member.id" :name="member.display_name || member.username" :muted="!member.active" class="ring-2 ring-background" />
          </div>
          <span class="whitespace-nowrap text-xs text-muted-foreground">{{ row.member_ids.length ? t("adminConsole.groups.membersCount", { count: row.member_ids.length }) : t("adminConsole.groups.noMembers") }}</span>
        </div>
      </template>
      <template #cell-permissions="{ row }">
        <AdminBadge :tone="grantCounts.get(row.id) ? 'primary' : 'neutral'">{{ t("adminConsole.groups.permissionsCount", { count: grantCounts.get(row.id) ?? 0 }) }}</AdminBadge>
      </template>
      <template #cell-actions="{ row }">
        <AdminRowMenu :actions="actionsFor(row)" :disabled="busyId === row.id" />
      </template>
      <template #footer>
        <AdminPagination v-model:page="table.page.value" v-model:page-size="table.pageSize.value" :page-count="table.pageCount.value" :total="table.total.value" />
      </template>
    </AdminDataTable>

    <GroupFormDialog v-model:open="formOpen" :group="editingGroup" @saved="onSaved" />
    <MemberPickerDialog v-model:open="pickerOpen" :group="pickerGroup" />
  </section>
</template>
