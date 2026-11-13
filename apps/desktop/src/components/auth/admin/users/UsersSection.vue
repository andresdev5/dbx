<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { RefreshCw, ShieldOff, ShieldUser, UserPlus, UserRoundCheck, UsersRound } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import type { ManagedUser } from "@/lib/auth/accessAdmin";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { useAdminNavigator } from "@/lib/auth/adminNavigation";
import { textMatches, useTableState } from "@/lib/auth/adminTable";
import AdminAvatar from "../shared/AdminAvatar.vue";
import AdminBadge from "../shared/AdminBadge.vue";
import AdminDataTable, { type AdminColumn } from "../shared/AdminDataTable.vue";
import AdminPagination from "../shared/AdminPagination.vue";
import AdminRowMenu from "../shared/AdminRowMenu.vue";
import AdminSearchInput from "../shared/AdminSearchInput.vue";
import AdminSectionHeader from "../shared/AdminSectionHeader.vue";
import AdminStatCard from "../shared/AdminStatCard.vue";
import { selectClass, useAdminText } from "../shared/adminUi";
import IssuedPasswordDialog from "./IssuedPasswordDialog.vue";
import UserFormDialog from "./UserFormDialog.vue";
import { useUserActions } from "./useUserActions";

const { t } = useI18n();
const { dateTime, date, relative } = useAdminText();
const directory = useAdminDirectory();
const navigator = useAdminNavigator();
const actions = useUserActions();

const roleFilter = ref<"" | "admin" | "user">("");
const statusFilter = ref<"" | "active" | "disabled">("");
const mfaFilter = ref<"" | "on" | "off" | "required">("");
const formOpen = ref(false);
const editingUser = ref<ManagedUser | null>(null);
const refreshing = ref(false);

const table = useTableState(directory.users, {
  matches: (user, query) => textMatches(query, user.username, user.display_name),
  filter: (user) => {
    if (roleFilter.value && user.role !== roleFilter.value) return false;
    if (statusFilter.value === "active" && !user.active) return false;
    if (statusFilter.value === "disabled" && user.active) return false;
    if (mfaFilter.value === "on" && !user.mfa_enabled) return false;
    if (mfaFilter.value === "off" && user.mfa_enabled) return false;
    if (mfaFilter.value === "required" && !user.mfa_required) return false;
    return true;
  },
  sorters: {
    user: (user) => (user.display_name || user.username).toLocaleLowerCase(),
    role: (user) => user.role,
    status: (user) => (user.active ? 0 : 1),
    lastLogin: (user) => user.last_login_at ?? null,
    created: (user) => user.created_at ?? null,
  },
  initialSort: { key: "user", direction: "asc" },
});

const columns = computed<AdminColumn[]>(() => [
  { key: "user", label: t("adminConsole.users.columns.user"), sortable: true },
  { key: "role", label: t("adminConsole.users.columns.role"), sortable: true },
  { key: "status", label: t("adminConsole.users.columns.status"), sortable: true },
  { key: "mfa", label: t("adminConsole.users.columns.mfa") },
  { key: "lastLogin", label: t("adminConsole.users.columns.lastLogin"), sortable: true, class: "whitespace-nowrap text-muted-foreground" },
  { key: "created", label: t("adminConsole.users.columns.created"), sortable: true, class: "hidden whitespace-nowrap text-muted-foreground lg:table-cell", headerClass: "hidden lg:table-cell" },
  { key: "actions", label: "", align: "right", class: "w-10" },
]);

const stats = computed(() => {
  const users = directory.users.value;
  return {
    total: users.length,
    active: users.filter((user) => user.active).length,
    admins: users.filter((user) => user.role === "admin").length,
    withoutMfa: users.filter((user) => user.active && !user.mfa_enabled).length,
  };
});

const hasFilters = computed(() => Boolean(table.query.value || roleFilter.value || statusFilter.value || mfaFilter.value));

function clearFilters() {
  table.query.value = "";
  roleFilter.value = "";
  statusFilter.value = "";
  mfaFilter.value = "";
}

function openCreate() {
  editingUser.value = null;
  formOpen.value = true;
}

function openEdit(user: ManagedUser) {
  editingUser.value = user;
  formOpen.value = true;
}

function openDetail(user: ManagedUser) {
  navigator.go({ section: "user", id: user.id });
}

async function refresh() {
  refreshing.value = true;
  await directory.refreshUsers();
  refreshing.value = false;
}

function mfaTone(user: ManagedUser): "success" | "warning" | "neutral" {
  if (user.mfa_enabled) return "success";
  return user.mfa_required ? "warning" : "neutral";
}

function mfaLabel(user: ManagedUser): string {
  if (user.mfa_enabled) return t("adminConsole.users.mfa.enabled");
  return user.mfa_required ? t("adminConsole.users.mfa.pending") : t("adminConsole.users.mfa.off");
}
</script>

<template>
  <section class="space-y-5" data-testid="admin-users">
    <AdminSectionHeader :title="t('adminConsole.sections.users')" :description="t('adminConsole.users.description')">
      <template #actions>
        <Button variant="outline" size="sm" :disabled="refreshing" @click="refresh">
          <RefreshCw :class="refreshing ? 'animate-spin' : ''" />
          {{ t("adminConsole.refresh") }}
        </Button>
        <Button size="sm" data-testid="admin-users-new" @click="openCreate">
          <UserPlus />
          {{ t("adminConsole.users.newUser") }}
        </Button>
      </template>
    </AdminSectionHeader>

    <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <AdminStatCard :label="t('adminConsole.users.stats.total')" :value="stats.total" :icon="UsersRound" />
      <AdminStatCard :label="t('adminConsole.users.stats.active')" :value="stats.active" :icon="UserRoundCheck" tone="success" />
      <AdminStatCard :label="t('adminConsole.users.stats.admins')" :value="stats.admins" :icon="ShieldUser" />
      <AdminStatCard :label="t('adminConsole.users.stats.withoutMfa')" :value="stats.withoutMfa" :icon="ShieldOff" :tone="stats.withoutMfa ? 'warning' : 'default'" />
    </div>

    <p v-if="actions.error.value" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive" data-testid="admin-users-error">{{ actions.error.value }}</p>

    <div class="flex flex-wrap items-center gap-2">
      <AdminSearchInput v-model="table.query.value" :placeholder="t('adminConsole.users.search')" />
      <select v-model="roleFilter" :class="[selectClass, 'w-auto']" :aria-label="t('adminConsole.users.filters.role')" data-testid="admin-users-role-filter">
        <option value="">{{ t("adminConsole.users.filters.anyRole") }}</option>
        <option value="admin">{{ t("auth.roleAdmin") }}</option>
        <option value="user">{{ t("auth.roleUser") }}</option>
      </select>
      <select v-model="statusFilter" :class="[selectClass, 'w-auto']" :aria-label="t('adminConsole.users.filters.status')" data-testid="admin-users-status-filter">
        <option value="">{{ t("adminConsole.users.filters.anyStatus") }}</option>
        <option value="active">{{ t("adminConsole.users.status.active") }}</option>
        <option value="disabled">{{ t("adminConsole.users.status.disabled") }}</option>
      </select>
      <select v-model="mfaFilter" :class="[selectClass, 'w-auto']" :aria-label="t('adminConsole.users.filters.mfa')" data-testid="admin-users-mfa-filter">
        <option value="">{{ t("adminConsole.users.filters.mfa") }}: {{ t("adminConsole.users.filters.anyMfa") }}</option>
        <option value="on">{{ t("adminConsole.users.filters.mfaOn") }}</option>
        <option value="off">{{ t("adminConsole.users.filters.mfaOff") }}</option>
        <option value="required">{{ t("adminConsole.users.filters.mfaRequired") }}</option>
      </select>
      <Button v-if="hasFilters" variant="ghost" size="sm" @click="clearFilters">{{ t("audit.clear") }}</Button>
    </div>

    <AdminDataTable
      :columns="columns"
      :rows="table.paged.value"
      :row-key="(user) => user.id"
      :loading="!directory.loaded.value"
      :empty-text="t('adminConsole.users.empty')"
      :empty-hint="hasFilters ? t('adminConsole.users.emptyHint') : ''"
      :sort-key="table.sortKey.value"
      :sort-direction="table.sortDirection.value"
      clickable
      :row-class="(user) => (user.active ? '' : 'opacity-60')"
      test-id="admin-users-table"
      @sort="table.toggleSort"
      @row-click="openDetail"
    >
      <template #cell-user="{ row }">
        <div class="flex min-w-0 items-center gap-2.5">
          <AdminAvatar :name="row.display_name || row.username" :muted="!row.active" />
          <div class="min-w-0">
            <p class="flex items-center gap-1.5 truncate font-medium">
              <span class="truncate">{{ row.display_name || row.username }}</span>
              <AdminBadge v-if="row.id === directory.currentUserId.value" tone="info">{{ t("adminConsole.you") }}</AdminBadge>
            </p>
            <p class="truncate text-xs text-muted-foreground">{{ row.username }}</p>
          </div>
        </div>
      </template>
      <template #cell-role="{ row }">
        <AdminBadge :tone="row.role === 'admin' ? 'primary' : 'neutral'">{{ row.role === "admin" ? t("auth.roleAdmin") : t("auth.roleUser") }}</AdminBadge>
      </template>
      <template #cell-status="{ row }">
        <div class="flex flex-wrap items-center gap-1">
          <AdminBadge :tone="row.active ? 'success' : 'neutral'" dot>{{ row.active ? t("adminConsole.users.status.active") : t("adminConsole.users.status.disabled") }}</AdminBadge>
          <AdminBadge v-if="row.must_change_password" tone="warning">{{ t("adminConsole.users.status.mustChange") }}</AdminBadge>
        </div>
      </template>
      <template #cell-mfa="{ row }">
        <AdminBadge :tone="mfaTone(row)" data-testid="mfa-badge">{{ mfaLabel(row) }}</AdminBadge>
      </template>
      <template #cell-lastLogin="{ row }">
        <span :title="dateTime(row.last_login_at)">{{ relative(row.last_login_at, t("adminConsole.never")) }}</span>
      </template>
      <template #cell-created="{ row }">
        {{ date(row.created_at) }}
      </template>
      <template #cell-actions="{ row }">
        <AdminRowMenu :actions="actions.actionsFor(row, { view: () => openDetail(row), edit: () => openEdit(row) })" :disabled="actions.busyId.value === row.id" />
      </template>
      <template #footer>
        <AdminPagination v-model:page="table.page.value" v-model:page-size="table.pageSize.value" :page-count="table.pageCount.value" :total="table.total.value" />
      </template>
    </AdminDataTable>

    <UserFormDialog v-model:open="formOpen" :user="editingUser" @created="(result) => result.temporary_password && (actions.issued.value = { username: result.user.username, password: result.temporary_password })" />
    <IssuedPasswordDialog :issued="actions.issued.value" @close="actions.issued.value = null" />
  </section>
</template>
