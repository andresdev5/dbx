<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { LogOut, RefreshCw } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { auditAdmin, type LiveSession } from "@/lib/auth/auditAdmin";
import { useAdminConfirm } from "@/lib/auth/adminConfirm";
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
import { selectClass, useAdminText } from "../shared/adminUi";

const props = defineProps<{ userId?: string; embedded?: boolean }>();
const { t } = useI18n();
const { dateTime, relative, errorText } = useAdminText();
const directory = useAdminDirectory();
const navigator = useAdminNavigator();
const confirm = useAdminConfirm();

const sessions = ref<LiveSession[]>([]);
const loading = ref(false);
const loaded = ref(false);
const busy = ref(false);
const error = ref("");
const userFilter = ref("");

const scopedUserId = computed(() => props.userId || userFilter.value);
const scopedUsername = computed(() => {
  const id = scopedUserId.value;
  if (!id) return "";
  return sessions.value.find((session) => session.user_id === id)?.username ?? directory.userLabel(id);
});
const revocableForUser = computed(() => Boolean(scopedUserId.value) && sessions.value.some((session) => session.user_id === scopedUserId.value && !session.current));

const userOptions = computed(() => {
  const options = new Map<string, string>();
  for (const session of sessions.value) options.set(session.user_id, session.username ?? directory.userLabel(session.user_id));
  return [...options.entries()].map(([id, label]) => ({ id, label })).sort((a, b) => a.label.localeCompare(b.label));
});

const table = useTableState(sessions, {
  matches: (session, query) => textMatches(query, session.username, session.user_id, session.ip, session.user_agent),
  filter: (session) => (!props.userId || session.user_id === props.userId) && (!userFilter.value || session.user_id === userFilter.value),
  sorters: {
    user: (session) => (session.username ?? session.user_id).toLocaleLowerCase(),
    ip: (session) => session.ip,
    started: (session) => session.created_at,
    lastSeen: (session) => session.last_seen_at,
    expires: (session) => session.expires_at,
  },
  initialSort: { key: "lastSeen", direction: "desc" },
});

const columns = computed<AdminColumn[]>(() => [
  ...(props.userId ? [] : [{ key: "user", label: t("adminConsole.sessions.columns.user"), sortable: true }]),
  { key: "ip", label: t("adminConsole.sessions.columns.ip"), sortable: true, class: "whitespace-nowrap font-mono text-xs" },
  { key: "client", label: t("adminConsole.sessions.columns.client"), class: "max-w-64" },
  { key: "started", label: t("adminConsole.sessions.columns.started"), sortable: true, class: "hidden whitespace-nowrap text-muted-foreground lg:table-cell", headerClass: "hidden lg:table-cell" },
  { key: "lastSeen", label: t("adminConsole.sessions.columns.lastSeen"), sortable: true, class: "whitespace-nowrap text-muted-foreground" },
  { key: "expires", label: t("adminConsole.sessions.columns.expires"), sortable: true, class: "whitespace-nowrap text-muted-foreground" },
  { key: "actions", label: "", align: "right", class: "w-10" },
]);

const hasFilters = computed(() => Boolean(table.query.value || userFilter.value));

function clearFilters() {
  table.query.value = "";
  userFilter.value = "";
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    sessions.value = await auditAdmin.sessions(props.userId);
  } catch (e) {
    error.value = errorText(e);
  } finally {
    loading.value = false;
    loaded.value = true;
  }
}

async function run(action: () => Promise<unknown>) {
  busy.value = true;
  error.value = "";
  try {
    await action();
    sessions.value = await auditAdmin.sessions(props.userId);
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}

async function revoke(session: LiveSession) {
  const username = session.username ?? session.user_id;
  if (!(await confirm({ title: t("sessions.confirmRevoke", { username }), description: t("adminConsole.sessions.confirm.revokeDescription"), confirmLabel: t("adminConsole.sessions.revoke"), destructive: true }))) return;
  await run(() => auditAdmin.revokeSession(session.id));
}

async function revokeAll() {
  const userId = scopedUserId.value;
  if (!userId) return;
  const username = scopedUsername.value;
  if (!(await confirm({ title: t("sessions.confirmRevokeAll", { username }), description: t("adminConsole.sessions.confirm.revokeAllDescription"), confirmLabel: t("sessions.revokeAll"), destructive: true }))) return;
  await run(() => auditAdmin.revokeUserSessions(userId));
}

function client(userAgent: string | null): string {
  if (!userAgent) return t("sessions.unknownClient");
  return userAgent.length > 80 ? `${userAgent.slice(0, 80)}…` : userAgent;
}

function openUser(session: LiveSession) {
  if (!props.embedded) navigator.go({ section: "user", id: session.user_id });
}

onMounted(() => {
  void load();
});
</script>

<template>
  <section :class="embedded ? 'space-y-3' : 'space-y-5'" data-testid="admin-sessions">
    <AdminSectionHeader v-if="!embedded" :title="t('adminConsole.sections.sessions')" :description="t('adminConsole.sessions.description')">
      <template #actions>
        <Button variant="outline" size="sm" :disabled="loading || busy" data-testid="admin-sessions-refresh" @click="load">
          <RefreshCw :class="loading ? 'animate-spin' : ''" />
          {{ t("adminConsole.refresh") }}
        </Button>
      </template>
    </AdminSectionHeader>

    <p v-if="error" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive" data-testid="admin-sessions-error">{{ error }}</p>

    <div class="flex flex-wrap items-center gap-2">
      <AdminSearchInput v-model="table.query.value" :placeholder="t('adminConsole.sessions.search')" />
      <select v-if="!userId" v-model="userFilter" :class="[selectClass, 'w-auto']" :aria-label="t('adminConsole.sessions.userFilter')" data-testid="admin-sessions-user-filter">
        <option value="">{{ t("adminConsole.sessions.anyUser") }}</option>
        <option v-for="option in userOptions" :key="option.id" :value="option.id">{{ option.label }}</option>
      </select>
      <Button v-if="hasFilters" variant="ghost" size="sm" @click="clearFilters">{{ t("audit.clear") }}</Button>
      <div class="ml-auto flex items-center gap-2">
        <Button v-if="revocableForUser" variant="destructive" size="sm" :disabled="busy" data-testid="sessions-revoke-all" @click="revokeAll">
          <LogOut />
          {{ t("adminConsole.sessions.revokeAllFor", { username: scopedUsername }) }}
        </Button>
        <Button v-if="embedded" variant="outline" size="sm" :disabled="loading || busy" data-testid="admin-sessions-refresh" @click="load">
          <RefreshCw :class="loading ? 'animate-spin' : ''" />
          {{ t("adminConsole.refresh") }}
        </Button>
      </div>
    </div>

    <AdminDataTable
      :columns="columns"
      :rows="table.paged.value"
      :row-key="(session) => session.id"
      :loading="!loaded"
      :empty-text="t('adminConsole.sessions.empty')"
      :empty-hint="hasFilters ? t('adminConsole.sessions.emptyHint') : ''"
      :sort-key="table.sortKey.value"
      :sort-direction="table.sortDirection.value"
      test-id="admin-sessions-table"
      @sort="table.toggleSort"
    >
      <template #cell-user="{ row }">
        <button type="button" class="flex min-w-0 items-center gap-2.5 text-left" :disabled="embedded" data-row-action @click="openUser(row)">
          <AdminAvatar :name="row.username ?? row.user_id" />
          <span class="truncate font-medium hover:underline">{{ row.username ?? row.user_id }}</span>
        </button>
      </template>
      <template #cell-ip="{ row }">
        <div class="flex items-center gap-1.5">
          <span>{{ row.ip ?? t("sessions.unknownIp") }}</span>
          <AdminBadge v-if="row.current" tone="success" dot data-testid="session-current">{{ t("adminConsole.sessions.current") }}</AdminBadge>
        </div>
      </template>
      <template #cell-client="{ row }">
        <span class="block truncate text-xs text-muted-foreground" :title="row.user_agent ?? ''">{{ client(row.user_agent) }}</span>
      </template>
      <template #cell-started="{ row }">{{ dateTime(row.created_at) }}</template>
      <template #cell-lastSeen="{ row }">
        <span :title="dateTime(row.last_seen_at)">{{ relative(row.last_seen_at) }}</span>
      </template>
      <template #cell-expires="{ row }">
        <span :title="dateTime(row.expires_at)">{{ row.expires_at ? relative(row.expires_at) : t("sessions.noLimit") }}</span>
      </template>
      <template #cell-actions="{ row }">
        <AdminRowMenu v-if="!row.current" :actions="[{ key: 'revoke', label: t('adminConsole.sessions.revoke'), icon: LogOut, destructive: true, action: () => void revoke(row) }]" :disabled="busy" />
      </template>
      <template #footer>
        <AdminPagination v-model:page="table.page.value" v-model:page-size="table.pageSize.value" :page-count="table.pageCount.value" :total="table.total.value" />
      </template>
    </AdminDataTable>
  </section>
</template>
