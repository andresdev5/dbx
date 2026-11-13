<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Copy, Pencil, Plus, RefreshCw, Trash2 } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { accessAdmin, describeResource, type Grant, type GrantSubject } from "@/lib/auth/accessAdmin";
import { useAdminConfirm } from "@/lib/auth/adminConfirm";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { useAdminNavigator } from "@/lib/auth/adminNavigation";
import { textMatches, useTableState } from "@/lib/auth/adminTable";
import AdminBadge from "../shared/AdminBadge.vue";
import AdminDataTable, { type AdminColumn } from "../shared/AdminDataTable.vue";
import AdminPagination from "../shared/AdminPagination.vue";
import AdminRowMenu, { type AdminRowAction } from "../shared/AdminRowMenu.vue";
import AdminSearchInput from "../shared/AdminSearchInput.vue";
import AdminSectionHeader from "../shared/AdminSectionHeader.vue";
import { selectClass, useAdminText } from "../shared/adminUi";
import GrantFormDialog from "./GrantFormDialog.vue";

const props = defineProps<{ subject?: GrantSubject; embedded?: boolean }>();
const { t } = useI18n();
const { date, errorText } = useAdminText();
const directory = useAdminDirectory();
const navigator = useAdminNavigator();
const confirm = useAdminConfirm();

const grants = ref<Grant[]>([]);
const loading = ref(true);
const busy = ref(false);
const error = ref("");
const now = ref(Date.now());
const selected = ref<string[]>([]);
const connectionFilter = ref("");
const subjectFilter = ref<"" | GrantSubject["kind"]>("");
const effectFilter = ref<"" | "allow" | "deny">("");
const statusFilter = ref<"" | "active" | "expired">("");
const formOpen = ref(false);
const editingGrant = ref<Grant | null>(null);
const duplicating = ref(false);

function isExpired(grant: Grant): boolean {
  return grant.expires_at !== null && grant.expires_at <= now.value;
}

function subjectLabel(subject: GrantSubject): string {
  if (subject.kind === "system") return t("access.subjectSystem");
  if (subject.kind === "user") return t("access.subjectUser", { name: directory.userLabel(subject.id) });
  return t("access.subjectGroup", { name: directory.groupLabel(subject.id) });
}

function scopeLabel(grant: Grant): string {
  if (grant.scope.kind === "all") return t("access.scopeAll");
  if (grant.scope.kind === "connection_group") return t("access.scopeConnectionGroup", { name: grant.scope.value });
  return describeResource(grant.scope.value, directory.connections.value);
}

function roleName(id: string): string {
  const role = directory.roles.value.find((candidate) => candidate.id === id);
  if (!role) return id;
  return role.builtin ? t(`access.builtinRoles.${role.name}`) : role.name;
}

const table = useTableState(grants, {
  matches: (grant, query) => textMatches(query, subjectLabel(grant.subject), scopeLabel(grant), grant.note, grant.role_id ? roleName(grant.role_id) : (grant.operations ?? []).join(" ")),
  filter: (grant) => {
    if (connectionFilter.value && grant.scope.kind === "resource" && grant.scope.value.connectionId !== connectionFilter.value) return false;
    if (subjectFilter.value && grant.subject.kind !== subjectFilter.value) return false;
    if (effectFilter.value && grant.effect !== effectFilter.value) return false;
    if (statusFilter.value === "active" && isExpired(grant)) return false;
    if (statusFilter.value === "expired" && !isExpired(grant)) return false;
    return true;
  },
  sorters: {
    effect: (grant) => grant.effect,
    subject: (grant) => subjectLabel(grant.subject).toLocaleLowerCase(),
    scope: (grant) => scopeLabel(grant).toLocaleLowerCase(),
    expires: (grant) => grant.expires_at,
  },
});

const columns = computed<AdminColumn[]>(() => {
  const all: AdminColumn[] = [
    { key: "effect", label: t("adminConsole.grants.columns.effect"), sortable: true, class: "w-24" },
    { key: "subject", label: t("adminConsole.grants.columns.subject"), sortable: true },
    { key: "scope", label: t("adminConsole.grants.columns.scope"), sortable: true },
    { key: "permissions", label: t("adminConsole.grants.columns.permissions") },
    { key: "expires", label: t("adminConsole.grants.columns.expires"), sortable: true, class: "whitespace-nowrap" },
    { key: "note", label: t("adminConsole.grants.columns.note"), class: "hidden max-w-48 truncate text-muted-foreground xl:table-cell", headerClass: "hidden xl:table-cell" },
    { key: "actions", label: "", align: "right", class: "w-10" },
  ];
  return props.subject ? all.filter((column) => column.key !== "subject") : all;
});

const expiredGrants = computed(() => table.filtered.value.filter(isExpired));
const hasFilters = computed(() => Boolean(table.query.value || connectionFilter.value || subjectFilter.value || effectFilter.value || statusFilter.value));

async function load() {
  now.value = Date.now();
  error.value = "";
  try {
    grants.value = await accessAdmin.grants(props.subject);
    const ids = new Set(grants.value.map((grant) => grant.id));
    selected.value = selected.value.filter((id) => ids.has(id));
  } catch (e) {
    error.value = errorText(e);
  } finally {
    loading.value = false;
  }
}

async function deleteMany(ids: string[]) {
  busy.value = true;
  error.value = "";
  try {
    for (const id of ids) await accessAdmin.deleteGrant(id);
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
    await load();
  }
}

async function remove(grant: Grant) {
  if (!(await confirm({ title: t("adminConsole.grants.confirm.deleteTitle"), description: t("adminConsole.grants.confirm.deleteDescription"), confirmLabel: t("adminConsole.grants.actions.delete"), destructive: true }))) return;
  await deleteMany([grant.id]);
}

async function removeSelected() {
  const ids = [...selected.value];
  if (!ids.length) return;
  if (!(await confirm({ title: t("adminConsole.grants.confirm.deleteSelectedTitle", { count: ids.length }), description: t("adminConsole.grants.confirm.deleteSelectedDescription"), confirmLabel: t("adminConsole.grants.actions.delete"), destructive: true }))) return;
  await deleteMany(ids);
}

async function removeExpired() {
  const ids = expiredGrants.value.map((grant) => grant.id);
  if (!ids.length) return;
  if (!(await confirm({ title: t("adminConsole.grants.confirm.removeExpiredTitle", { count: ids.length }), description: t("adminConsole.grants.confirm.removeExpiredDescription"), confirmLabel: t("access.removeExpired"), destructive: true }))) return;
  await deleteMany(ids);
}

function openForm(grant: Grant | null, duplicate = false) {
  editingGrant.value = grant;
  duplicating.value = duplicate;
  formOpen.value = true;
}

function openSubject(subject: GrantSubject) {
  if (subject.kind === "user") navigator.go({ section: "user", id: subject.id });
  else if (subject.kind === "group") navigator.go({ section: "group", id: subject.id });
}

function rowActions(grant: Grant): AdminRowAction[] {
  return [
    { key: "edit", label: t("adminConsole.grants.actions.edit"), icon: Pencil, action: () => openForm(grant) },
    { key: "duplicate", label: t("adminConsole.grants.actions.duplicate"), icon: Copy, action: () => openForm(grant, true) },
    { key: "separator", separator: true },
    { key: "delete", label: t("adminConsole.grants.actions.delete"), icon: Trash2, destructive: true, action: () => void remove(grant) },
  ];
}

function clearFilters() {
  table.query.value = "";
  connectionFilter.value = "";
  subjectFilter.value = "";
  effectFilter.value = "";
  statusFilter.value = "";
}

onMounted(() => {
  void load();
});
</script>

<template>
  <section class="space-y-4" data-testid="access-grants">
    <AdminSectionHeader v-if="!embedded" :title="t('adminConsole.sections.grants')" :description="t('adminConsole.grants.description')">
      <template #actions>
        <Button variant="outline" size="sm" :disabled="busy" @click="load">
          <RefreshCw />
          {{ t("adminConsole.refresh") }}
        </Button>
        <Button size="sm" data-testid="grant-new" @click="openForm(null)">
          <Plus />
          {{ t("access.newGrant") }}
        </Button>
      </template>
    </AdminSectionHeader>
    <div v-else class="flex items-center justify-between gap-2">
      <p class="text-sm text-muted-foreground">{{ t("adminConsole.grants.count", { count: grants.length }) }}</p>
      <Button size="sm" data-testid="grant-new" @click="openForm(null)">
        <Plus />
        {{ t("access.newGrant") }}
      </Button>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive" data-testid="grants-error">{{ error }}</p>

    <div class="flex flex-wrap items-center gap-2">
      <AdminSearchInput v-model="table.query.value" :placeholder="t('adminConsole.grants.search')" />
      <template v-if="!embedded">
        <select v-model="connectionFilter" :class="[selectClass, 'w-auto']" :aria-label="t('access.filterConnection')" data-testid="grant-filter">
          <option value="">{{ t("access.allConnections") }}</option>
          <option v-for="connection in directory.connections.value" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
        </select>
        <select v-model="subjectFilter" :class="[selectClass, 'w-auto']" :aria-label="t('adminConsole.grants.filters.subjectKind')" data-testid="grant-subject-filter">
          <option value="">{{ t("adminConsole.grants.filters.anySubject") }}</option>
          <option value="user">{{ t("access.subjectKindUser") }}</option>
          <option value="group">{{ t("access.subjectKindGroup") }}</option>
          <option value="system">{{ t("access.subjectSystem") }}</option>
        </select>
      </template>
      <select v-model="effectFilter" :class="[selectClass, 'w-auto']" :aria-label="t('adminConsole.grants.filters.effect')" data-testid="grant-effect-filter">
        <option value="">{{ t("adminConsole.grants.filters.anyEffect") }}</option>
        <option value="allow">{{ t("access.allow") }}</option>
        <option value="deny">{{ t("access.deny") }}</option>
      </select>
      <select v-model="statusFilter" :class="[selectClass, 'w-auto']" :aria-label="t('adminConsole.grants.filters.status')" data-testid="grant-status-filter">
        <option value="">{{ t("adminConsole.grants.filters.anyStatus") }}</option>
        <option value="active">{{ t("adminConsole.grants.filters.active") }}</option>
        <option value="expired">{{ t("adminConsole.grants.filters.expired") }}</option>
      </select>
      <Button v-if="hasFilters" variant="ghost" size="sm" @click="clearFilters">{{ t("audit.clear") }}</Button>
    </div>

    <div v-if="selected.length || expiredGrants.length" class="flex flex-wrap items-center gap-2 rounded-md bg-muted/40 px-3 py-2 text-sm">
      <template v-if="selected.length">
        <span class="text-muted-foreground" data-testid="grant-selection">{{ t("adminConsole.table.selected", { count: selected.length }) }}</span>
        <Button variant="destructive" size="sm" :disabled="busy" data-testid="grant-delete-selected" @click="removeSelected">
          <Trash2 />
          {{ t("adminConsole.grants.deleteSelected", { count: selected.length }) }}
        </Button>
        <Button variant="ghost" size="sm" @click="selected = []">{{ t("adminConsole.table.clearSelection") }}</Button>
      </template>
      <div v-if="expiredGrants.length" class="ml-auto flex items-center gap-2" data-testid="grant-expired-summary">
        <span class="text-muted-foreground">{{ t("access.expiredCount", { count: expiredGrants.length }) }}</span>
        <Button variant="ghost" size="sm" class="text-destructive hover:text-destructive" :disabled="busy" data-testid="grant-remove-expired" @click="removeExpired">
          {{ t("adminConsole.grants.removeExpired", { count: expiredGrants.length }) }}
        </Button>
      </div>
    </div>

    <AdminDataTable
      v-model:selected="selected"
      :columns="columns"
      :rows="table.paged.value"
      :row-key="(grant) => grant.id"
      :loading="loading"
      :empty-text="subject && !hasFilters ? t('adminConsole.grants.emptySubject') : t('adminConsole.grants.empty')"
      :empty-hint="subject ? '' : t('adminConsole.grants.emptyHint')"
      :sort-key="table.sortKey.value"
      :sort-direction="table.sortDirection.value"
      selectable
      :row-class="(grant) => (isExpired(grant) ? 'opacity-60' : '')"
      test-id="access-grant"
      @sort="table.toggleSort"
    >
      <template #cell-effect="{ row }">
        <AdminBadge :tone="row.effect === 'deny' ? 'danger' : 'success'" dot>{{ row.effect === "deny" ? t("access.deny") : t("access.allow") }}</AdminBadge>
      </template>
      <template #cell-subject="{ row }">
        <button v-if="row.subject.kind !== 'system'" type="button" class="truncate text-left font-medium hover:underline" data-testid="grant-subject-link" @click="openSubject(row.subject)">{{ subjectLabel(row.subject) }}</button>
        <span v-else class="font-medium">{{ subjectLabel(row.subject) }}</span>
      </template>
      <template #cell-scope="{ row }">
        <span :class="row.scope.kind === 'resource' ? 'font-mono text-xs' : 'text-sm'">{{ scopeLabel(row) }}</span>
      </template>
      <template #cell-permissions="{ row }">
        <AdminBadge v-if="row.role_id" tone="primary">{{ roleName(row.role_id) }}</AdminBadge>
        <div v-else class="flex flex-wrap gap-1">
          <AdminBadge v-for="operation in row.operations ?? []" :key="operation" mono>{{ operation }}</AdminBadge>
        </div>
      </template>
      <template #cell-expires="{ row }">
        <div class="flex flex-wrap items-center gap-1.5">
          <span :class="row.expires_at ? '' : 'text-muted-foreground'">{{ row.expires_at ? date(row.expires_at) : t("adminConsole.grants.noExpiry") }}</span>
          <AdminBadge v-if="isExpired(row)" tone="neutral" data-testid="grant-expired">{{ t("access.expired") }}</AdminBadge>
        </div>
      </template>
      <template #cell-note="{ row }">
        <span :title="row.note ?? ''">{{ row.note }}</span>
      </template>
      <template #cell-actions="{ row }">
        <AdminRowMenu :actions="rowActions(row)" :disabled="busy" />
      </template>
      <template #footer>
        <AdminPagination v-model:page="table.page.value" v-model:page-size="table.pageSize.value" :page-count="table.pageCount.value" :total="table.total.value" />
      </template>
    </AdminDataTable>

    <GrantFormDialog v-model:open="formOpen" :grant="editingGrant" :duplicate="duplicating" :locked-subject="subject" :preset-connection="connectionFilter" @saved="load" />
  </section>
</template>
