<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { ArrowLeft, Pencil, Trash2, UserMinus, UserPlus, Users } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { accessAdmin, type ManagedUser } from "@/lib/auth/accessAdmin";
import { useAdminConfirm } from "@/lib/auth/adminConfirm";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { useAdminNavigator } from "@/lib/auth/adminNavigation";
import { textMatches, useTableState } from "@/lib/auth/adminTable";
import GrantsSection from "../grants/GrantsSection.vue";
import AdminAvatar from "../shared/AdminAvatar.vue";
import AdminBadge from "../shared/AdminBadge.vue";
import AdminDataTable, { type AdminColumn } from "../shared/AdminDataTable.vue";
import AdminPagination from "../shared/AdminPagination.vue";
import AdminSearchInput from "../shared/AdminSearchInput.vue";
import AdminTabs from "../shared/AdminTabs.vue";
import { useAdminText } from "../shared/adminUi";
import GroupFormDialog from "./GroupFormDialog.vue";
import MemberPickerDialog from "./MemberPickerDialog.vue";

const props = defineProps<{ groupId: string; tab?: string }>();
const { t } = useI18n();
const { errorText, relative, dateTime } = useAdminText();
const directory = useAdminDirectory();
const navigator = useAdminNavigator();
const confirm = useAdminConfirm();

const activeTab = ref(props.tab ?? "members");
const formOpen = ref(false);
const pickerOpen = ref(false);
const busy = ref(false);
const busyMember = ref("");
const error = ref("");

const group = computed(() => directory.groups.value.find((candidate) => candidate.id === props.groupId) ?? null);
const members = computed<ManagedUser[]>(() => {
  const ids = new Set(group.value?.member_ids ?? []);
  return directory.users.value.filter((user) => ids.has(user.id));
});

const table = useTableState(members, {
  matches: (user, query) => textMatches(query, user.username, user.display_name),
  sorters: {
    user: (user) => (user.display_name || user.username).toLocaleLowerCase(),
    role: (user) => user.role,
    lastLogin: (user) => user.last_login_at ?? null,
  },
  initialSort: { key: "user", direction: "asc" },
});

const columns = computed<AdminColumn[]>(() => [
  { key: "user", label: t("adminConsole.users.columns.user"), sortable: true },
  { key: "role", label: t("adminConsole.users.columns.role"), sortable: true },
  { key: "lastLogin", label: t("adminConsole.users.columns.lastLogin"), sortable: true, class: "whitespace-nowrap text-muted-foreground" },
  { key: "actions", label: "", align: "right", class: "w-10" },
]);

const tabs = computed(() => [
  { key: "members", label: t("adminConsole.groups.detail.tabs.members"), count: members.value.length },
  { key: "permissions", label: t("adminConsole.groups.detail.tabs.permissions") },
]);

function back() {
  navigator.go({ section: "groups" });
}

async function removeGroup() {
  if (!group.value) return;
  const current = group.value;
  if (!(await confirm({ title: t("adminConsole.groups.confirm.deleteTitle", { name: current.name }), description: t("adminConsole.groups.confirm.deleteDescription"), confirmLabel: t("adminConsole.groups.actions.delete"), destructive: true }))) return;
  busy.value = true;
  error.value = "";
  try {
    await accessAdmin.deleteGroup(current.id);
    await directory.refreshGroups();
    back();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}

async function removeMember(user: ManagedUser) {
  if (!group.value) return;
  const current = group.value;
  if (!(await confirm({ title: t("adminConsole.groups.confirm.removeMemberTitle", { username: user.username, name: current.name }), description: t("adminConsole.groups.confirm.removeMemberDescription"), confirmLabel: t("adminConsole.groups.detail.removeMember"), destructive: true }))) return;
  busyMember.value = user.id;
  error.value = "";
  try {
    await accessAdmin.setGroupMembers(
      current.id,
      current.member_ids.filter((id) => id !== user.id),
    );
    await directory.refreshGroups();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busyMember.value = "";
  }
}
</script>

<template>
  <section class="space-y-5" data-testid="admin-group-detail">
    <button type="button" class="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground" data-testid="admin-group-back" @click="back">
      <ArrowLeft class="h-4 w-4" />
      {{ t("adminConsole.groups.detail.backToGroups") }}
    </button>

    <div v-if="!group && directory.loaded.value" class="rounded-lg border border-dashed border-border px-4 py-10 text-center text-sm text-muted-foreground">{{ t("adminConsole.groups.detail.notFound") }}</div>

    <template v-else-if="group">
      <div class="flex flex-wrap items-start gap-4">
        <span class="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <Users class="h-5 w-5" />
        </span>
        <div class="min-w-0 flex-1 space-y-1.5">
          <h2 class="text-xl font-semibold tracking-tight">{{ group.name }}</h2>
          <p v-if="group.description" class="max-w-3xl text-sm text-muted-foreground">{{ group.description }}</p>
          <AdminBadge>{{ t("adminConsole.groups.membersCount", { count: group.member_ids.length }) }}</AdminBadge>
        </div>
        <div class="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" data-testid="admin-group-edit" @click="formOpen = true">
            <Pencil />
            {{ t("adminConsole.groups.actions.edit") }}
          </Button>
          <Button variant="destructive" size="sm" :disabled="busy" data-testid="admin-group-delete" @click="removeGroup">
            <Trash2 />
            {{ t("adminConsole.groups.actions.delete") }}
          </Button>
        </div>
      </div>

      <p v-if="error" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive" data-testid="admin-group-error">{{ error }}</p>

      <AdminTabs v-model="activeTab" :tabs="tabs" />

      <div v-if="activeTab === 'members'" class="space-y-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <AdminSearchInput v-model="table.query.value" :placeholder="t('adminConsole.groups.detail.searchMembers')" />
          <Button size="sm" data-testid="admin-group-add-members" @click="pickerOpen = true">
            <UserPlus />
            {{ t("adminConsole.groups.detail.addMembers") }}
          </Button>
        </div>
        <AdminDataTable
          :columns="columns"
          :rows="table.paged.value"
          :row-key="(user) => user.id"
          :loading="!directory.loaded.value"
          :empty-text="table.query.value ? t('adminConsole.users.empty') : t('adminConsole.groups.detail.noMembers')"
          :empty-hint="table.query.value ? '' : t('adminConsole.groups.detail.noMembersHint')"
          :sort-key="table.sortKey.value"
          :sort-direction="table.sortDirection.value"
          clickable
          test-id="admin-group-members"
          @sort="table.toggleSort"
          @row-click="(user) => navigator.go({ section: 'user', id: user.id })"
        >
          <template #cell-user="{ row }">
            <div class="flex min-w-0 items-center gap-2.5">
              <AdminAvatar :name="row.display_name || row.username" :muted="!row.active" />
              <div class="min-w-0">
                <p class="truncate font-medium">{{ row.display_name || row.username }}</p>
                <p class="truncate text-xs text-muted-foreground">{{ row.username }}</p>
              </div>
            </div>
          </template>
          <template #cell-role="{ row }">
            <AdminBadge :tone="row.role === 'admin' ? 'primary' : 'neutral'">{{ row.role === "admin" ? t("auth.roleAdmin") : t("auth.roleUser") }}</AdminBadge>
          </template>
          <template #cell-lastLogin="{ row }">
            <span :title="dateTime(row.last_login_at)">{{ relative(row.last_login_at, t("adminConsole.never")) }}</span>
          </template>
          <template #cell-actions="{ row }">
            <Button
              variant="ghost"
              size="icon-sm"
              class="text-destructive hover:text-destructive"
              :disabled="busyMember === row.id"
              :title="t('adminConsole.groups.detail.removeMember')"
              :aria-label="t('adminConsole.groups.detail.removeMember')"
              data-row-action
              data-testid="admin-group-remove-member"
              @click="removeMember(row)"
            >
              <UserMinus />
            </Button>
          </template>
          <template #footer>
            <AdminPagination v-model:page="table.page.value" v-model:page-size="table.pageSize.value" :page-count="table.pageCount.value" :total="table.total.value" />
          </template>
        </AdminDataTable>
      </div>

      <div v-else-if="activeTab === 'permissions'" class="space-y-3">
        <p class="text-sm text-muted-foreground">{{ t("adminConsole.groups.detail.permissionsDescription") }}</p>
        <GrantsSection :subject="{ kind: 'group', id: group.id }" embedded />
      </div>

      <GroupFormDialog v-model:open="formOpen" :group="group" />
      <MemberPickerDialog v-model:open="pickerOpen" :group="group" />
    </template>
  </section>
</template>
