<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useI18n } from "vue-i18n";
import { ChevronLeft, ChevronRight, Download, Filter, Loader2, RefreshCw, Search } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AUDIT_EVENTS, auditAdmin, downloadText, endOfDayMillis, startOfDay, type AuditEntry, type AuditQuery } from "@/lib/auth/auditAdmin";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import AdminBadge from "../shared/AdminBadge.vue";
import AdminDataTable, { type AdminColumn } from "../shared/AdminDataTable.vue";
import AdminSectionHeader from "../shared/AdminSectionHeader.vue";
import { checkboxClass, fieldLabelClass, selectClass, useAdminText } from "../shared/adminUi";
import AuditEntryDialog from "./AuditEntryDialog.vue";

const props = defineProps<{ userId?: string; embedded?: boolean }>();
const { t, te } = useI18n();
const { dateTime, errorText } = useAdminText();
const directory = useAdminDirectory();

const PAGE_SIZES = [25, 50, 100] as const;

const entries = ref<AuditEntry[]>([]);
const nextBeforeId = ref<number | null>(null);
const cursors = ref<(number | undefined)[]>([undefined]);
const pageIndex = ref(0);
const pageSize = ref(50);
const droppedEvents = ref(0);
const loading = ref(false);
const loaded = ref(false);
const exporting = ref(false);
const error = ref("");
const notice = ref("");
const includeStatements = ref(false);
const filtersOpen = ref(!props.embedded);
const selected = ref<AuditEntry | null>(null);
const filters = reactive({ userId: "", connectionId: "", decision: "", event: "", from: "", to: "", statement: "" });

const activeFilterCount = computed(() => Object.entries(filters).filter(([key, value]) => value && !(key === "userId" && props.userId)).length);

const columns = computed<AdminColumn[]>(() => [
  { key: "time", label: t("adminConsole.audit.columns.time"), class: "whitespace-nowrap text-xs text-muted-foreground" },
  { key: "event", label: t("adminConsole.audit.columns.event") },
  ...(props.userId ? [] : [{ key: "actor", label: t("adminConsole.audit.columns.actor") }]),
  { key: "target", label: t("adminConsole.audit.columns.target"), class: "max-w-72" },
  { key: "operations", label: t("adminConsole.audit.columns.operations"), class: "hidden lg:table-cell", headerClass: "hidden lg:table-cell" },
  { key: "decision", label: t("adminConsole.audit.columns.decision") },
  { key: "outcome", label: t("adminConsole.audit.columns.outcome"), align: "right", class: "whitespace-nowrap text-xs text-muted-foreground" },
]);

function query(): AuditQuery {
  return {
    user_id: props.userId || filters.userId,
    connection_id: filters.connectionId,
    decision: (filters.decision || undefined) as AuditQuery["decision"],
    event: filters.event,
    from: startOfDay(filters.from),
    to: endOfDayMillis(filters.to),
    statement: filters.statement,
    limit: pageSize.value,
  };
}

async function load(cursor: number | undefined) {
  loading.value = true;
  error.value = "";
  try {
    const page = await auditAdmin.list({ ...query(), before_id: cursor });
    entries.value = page.entries;
    nextBeforeId.value = page.next_before_id;
    droppedEvents.value = page.dropped_events;
  } catch (e) {
    error.value = errorText(e);
  } finally {
    loading.value = false;
    loaded.value = true;
  }
}

function search() {
  notice.value = "";
  cursors.value = [undefined];
  pageIndex.value = 0;
  void load(undefined);
}

function next() {
  if (nextBeforeId.value === null) return;
  cursors.value = [...cursors.value.slice(0, pageIndex.value + 1), nextBeforeId.value];
  pageIndex.value += 1;
  void load(cursors.value[pageIndex.value]);
}

function previous() {
  if (pageIndex.value === 0) return;
  pageIndex.value -= 1;
  void load(cursors.value[pageIndex.value]);
}

function changePageSize(size: number) {
  pageSize.value = size;
  search();
}

function resetFilters() {
  Object.assign(filters, { userId: "", connectionId: "", decision: "", event: "", from: "", to: "", statement: "" });
  search();
}

async function exportCsv() {
  exporting.value = true;
  error.value = "";
  notice.value = "";
  try {
    const { limit: _limit, ...rest } = query();
    const result = await auditAdmin.export({ ...rest, include_statements: includeStatements.value });
    downloadText(result.filename, result.content);
    if (result.truncated) notice.value = t("audit.exportTruncated");
  } catch (e) {
    error.value = errorText(e);
  } finally {
    exporting.value = false;
  }
}

function eventLabel(event: string): string {
  return te(`audit.events.${event}`) ? t(`audit.events.${event}`) : event;
}

function actorLabel(entry: AuditEntry): string {
  if (entry.acting_principal === "system") return entry.task_id ? t("audit.systemTask", { task: entry.task_id }) : t("audit.system");
  if (entry.acting_principal === "local") return t("audit.local");
  return entry.username ?? entry.user_id ?? t("audit.anonymous");
}

function target(entry: AuditEntry): string {
  const connection = entry.connection_id ? directory.connectionLabel(entry.connection_id) : "";
  return [connection, entry.database_name, entry.schema_name, entry.table_names].filter(Boolean).join(" / ");
}

function outcome(entry: AuditEntry): string {
  const parts: string[] = [];
  if (entry.rows_affected !== null) parts.push(t("adminConsole.audit.rows", { count: entry.rows_affected }));
  if (entry.duration_ms !== null) parts.push(t("audit.durationMs", { ms: entry.duration_ms }));
  return parts.join(" · ");
}

onMounted(() => {
  search();
});
</script>

<template>
  <section :class="embedded ? 'space-y-3' : 'space-y-5'" data-testid="audit-log">
    <AdminSectionHeader v-if="!embedded" :title="t('adminConsole.sections.audit')" :description="t('adminConsole.audit.description')">
      <template #actions>
        <Button variant="outline" size="sm" :disabled="loading" @click="load(cursors[pageIndex])">
          <RefreshCw :class="loading ? 'animate-spin' : ''" />
          {{ t("adminConsole.refresh") }}
        </Button>
      </template>
    </AdminSectionHeader>

    <div class="rounded-lg border border-border/70">
      <div class="flex flex-wrap items-center gap-2 px-3 py-2">
        <Button variant="ghost" size="sm" :aria-expanded="filtersOpen" data-testid="audit-toggle-filters" @click="filtersOpen = !filtersOpen">
          <Filter />
          {{ filtersOpen ? t("adminConsole.audit.hideFilters") : t("adminConsole.audit.showFilters") }}
        </Button>
        <AdminBadge v-if="activeFilterCount" tone="primary">{{ t("adminConsole.audit.activeFilters", { count: activeFilterCount }) }}</AdminBadge>
        <div class="ml-auto flex flex-wrap items-center gap-2">
          <label class="flex items-center gap-2 text-xs text-muted-foreground">
            <input v-model="includeStatements" type="checkbox" :class="checkboxClass" data-testid="audit-include-statements" />
            {{ t("audit.includeStatements") }}
          </label>
          <Button variant="outline" size="sm" :disabled="exporting" data-testid="audit-export" @click="exportCsv">
            <Loader2 v-if="exporting" class="animate-spin" />
            <Download v-else />
            {{ t("audit.export") }}
          </Button>
          <Button v-if="embedded" variant="outline" size="sm" :disabled="loading" @click="load(cursors[pageIndex])">
            <RefreshCw :class="loading ? 'animate-spin' : ''" />
            {{ t("adminConsole.refresh") }}
          </Button>
        </div>
      </div>
      <form v-show="filtersOpen" class="space-y-3 border-t border-border/70 px-3 py-3" data-testid="audit-filters" @submit.prevent="search">
        <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <label v-if="!userId" :class="['block', fieldLabelClass]">
            {{ t("audit.user") }}
            <select v-model="filters.userId" :class="selectClass" data-testid="audit-user">
              <option value="">{{ t("audit.anyUser") }}</option>
              <option v-for="user in directory.users.value" :key="user.id" :value="user.id">{{ user.username }}</option>
            </select>
          </label>
          <label :class="['block', fieldLabelClass]">
            {{ t("access.connection") }}
            <select v-model="filters.connectionId" :class="selectClass" data-testid="audit-connection">
              <option value="">{{ t("access.allConnections") }}</option>
              <option v-for="connection in directory.connections.value" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
            </select>
          </label>
          <label :class="['block', fieldLabelClass]">
            {{ t("audit.event") }}
            <select v-model="filters.event" :class="selectClass" data-testid="audit-event">
              <option value="">{{ t("audit.anyEvent") }}</option>
              <option v-for="event in AUDIT_EVENTS" :key="event" :value="event">{{ eventLabel(event) }}</option>
            </select>
          </label>
          <label :class="['block', fieldLabelClass]">
            {{ t("audit.decision") }}
            <select v-model="filters.decision" :class="selectClass" data-testid="audit-decision">
              <option value="">{{ t("audit.anyDecision") }}</option>
              <option value="allow">{{ t("audit.allowed") }}</option>
              <option value="deny">{{ t("audit.denied") }}</option>
            </select>
          </label>
          <label :class="['block', fieldLabelClass]">
            {{ t("audit.from") }}
            <Input v-model="filters.from" type="date" data-testid="audit-from" />
          </label>
          <label :class="['block', fieldLabelClass]">
            {{ t("audit.to") }}
            <Input v-model="filters.to" type="date" data-testid="audit-to" />
          </label>
        </div>
        <label :class="['block', fieldLabelClass]">
          {{ t("audit.statementSearch") }}
          <textarea
            v-model="filters.statement"
            rows="2"
            class="w-full rounded-md border border-input bg-transparent px-2.5 py-1.5 font-mono text-xs text-foreground outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
            :placeholder="t('audit.statementSearchHint')"
            data-testid="audit-statement"
          />
        </label>
        <div class="flex justify-end gap-2">
          <Button type="button" variant="ghost" size="sm" @click="resetFilters">{{ t("audit.clear") }}</Button>
          <Button type="submit" size="sm" :disabled="loading" data-testid="audit-search">
            <Search />
            {{ t("adminConsole.audit.apply") }}
          </Button>
        </div>
      </form>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive" data-testid="audit-error">{{ error }}</p>
    <p v-if="notice" class="rounded-md bg-muted px-3 py-2 text-sm text-muted-foreground" data-testid="audit-notice">{{ notice }}</p>
    <p v-if="droppedEvents" class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300" data-testid="audit-dropped">{{ t("audit.droppedEvents", { count: droppedEvents }) }}</p>

    <AdminDataTable
      :columns="columns"
      :rows="entries"
      :row-key="(entry) => String(entry.id)"
      :loading="loading || !loaded"
      :empty-text="t('audit.empty')"
      :empty-hint="activeFilterCount ? t('adminConsole.audit.emptyHint') : ''"
      clickable
      test-id="audit-entry"
      @row-click="(entry) => (selected = entry)"
    >
      <template #cell-time="{ row }">{{ dateTime(row.ts) }}</template>
      <template #cell-event="{ row }">
        <span class="font-medium">{{ eventLabel(row.event) }}</span>
      </template>
      <template #cell-actor="{ row }">
        <span class="truncate">{{ actorLabel(row) }}</span>
      </template>
      <template #cell-target="{ row }">
        <span class="block truncate text-muted-foreground" :title="target(row)">{{ target(row) || "—" }}</span>
      </template>
      <template #cell-operations="{ row }">
        <div class="flex flex-wrap gap-1">
          <AdminBadge v-for="operation in row.operations" :key="operation" mono>{{ operation }}</AdminBadge>
        </div>
      </template>
      <template #cell-decision="{ row }">
        <AdminBadge v-if="row.decision" :tone="row.decision === 'deny' ? 'danger' : 'success'" dot>{{ row.decision === "deny" ? t("audit.denied") : t("audit.allowed") }}</AdminBadge>
      </template>
      <template #cell-outcome="{ row }">{{ outcome(row) }}</template>
      <template #footer>
        <div class="flex flex-wrap items-center justify-between gap-3 border-t border-border/70 bg-muted/20 px-3 py-2 text-xs text-muted-foreground" data-testid="audit-pagination">
          <label class="flex items-center gap-1.5">
            {{ t("adminConsole.table.perPage") }}
            <select class="h-7 rounded-md border border-input bg-background px-1.5 text-xs text-foreground" :value="pageSize" data-testid="audit-page-size" @change="changePageSize(Number(($event.target as HTMLSelectElement).value))">
              <option v-for="size in PAGE_SIZES" :key="size" :value="size">{{ size }}</option>
            </select>
          </label>
          <nav class="flex items-center gap-1" :aria-label="t('adminConsole.table.pagination')">
            <Button variant="ghost" size="icon-xs" :disabled="pageIndex === 0 || loading" :aria-label="t('adminConsole.table.previous')" data-testid="audit-previous" @click="previous"><ChevronLeft /></Button>
            <span class="px-2 tabular-nums" data-testid="audit-page">{{ t("adminConsole.audit.page", { page: pageIndex + 1 }) }}</span>
            <Button variant="ghost" size="icon-xs" :disabled="nextBeforeId === null || loading" :aria-label="t('adminConsole.table.next')" data-testid="audit-next" @click="next"><ChevronRight /></Button>
          </nav>
        </div>
      </template>
    </AdminDataTable>

    <AuditEntryDialog :entry="selected" :event-label="selected ? eventLabel(selected.event) : ''" :actor="selected ? actorLabel(selected) : ''" :target="selected ? target(selected) : ''" @close="selected = null" />
  </section>
</template>
