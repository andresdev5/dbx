<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ChevronDown, ChevronRight, Download, Loader2, Search } from "@lucide/vue";
import { translateBackendError } from "@/i18n/backend-errors";
import { accessAdmin, listConnections, type ConnectionSummary, type ManagedUser } from "@/lib/auth/accessAdmin";
import { AUDIT_EVENTS, auditAdmin, downloadText, endOfDayMillis, startOfDay, type AuditEntry, type AuditQuery } from "@/lib/auth/auditAdmin";

const { t, te } = useI18n();

const PAGE_SIZE = 50;
const selectClass = "h-9 w-full rounded-md border border-input bg-background px-2 text-sm";

const users = ref<ManagedUser[]>([]);
const connections = ref<ConnectionSummary[]>([]);
const entries = ref<AuditEntry[]>([]);
const nextBeforeId = ref<number | null>(null);
const droppedEvents = ref(0);
const loading = ref(false);
const exporting = ref(false);
const error = ref("");
const notice = ref("");
const expanded = ref<Record<number, boolean>>({});
const revealed = ref<Record<string, string>>({});
const revealing = ref("");
const includeStatements = ref(false);
const filters = reactive({ userId: "", connectionId: "", decision: "", event: "", from: "", to: "", statement: "" });

const connectionNames = computed(() => new Map(connections.value.map((connection) => [connection.id, connection.name])));

function errorText(e: unknown): string {
  return translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("users.actionFailed");
}

function query(): AuditQuery {
  return {
    user_id: filters.userId,
    connection_id: filters.connectionId,
    decision: (filters.decision || undefined) as AuditQuery["decision"],
    event: filters.event,
    from: startOfDay(filters.from),
    to: endOfDayMillis(filters.to),
    statement: filters.statement,
    limit: PAGE_SIZE,
  };
}

async function search(more = false) {
  loading.value = true;
  error.value = "";
  notice.value = "";
  try {
    const page = await auditAdmin.list({ ...query(), before_id: more ? (nextBeforeId.value ?? undefined) : undefined });
    entries.value = more ? [...entries.value, ...page.entries] : page.entries;
    nextBeforeId.value = page.next_before_id;
    droppedEvents.value = page.dropped_events;
    if (!more) expanded.value = {};
  } catch (e) {
    error.value = errorText(e);
  } finally {
    loading.value = false;
  }
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

async function reveal(entry: AuditEntry) {
  revealing.value = entry.event_id;
  error.value = "";
  try {
    revealed.value = { ...revealed.value, [entry.event_id]: await auditAdmin.reveal(entry.event_id) };
  } catch (e) {
    error.value = errorText(e);
  } finally {
    revealing.value = "";
  }
}

function toggle(entry: AuditEntry) {
  expanded.value = { ...expanded.value, [entry.id]: !expanded.value[entry.id] };
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
  const connection = entry.connection_id ? (connectionNames.value.get(entry.connection_id) ?? entry.connection_id) : "";
  return [connection, entry.database_name, entry.schema_name, entry.table_names].filter(Boolean).join(" / ");
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleString();
}

function resetFilters() {
  Object.assign(filters, { userId: "", connectionId: "", decision: "", event: "", from: "", to: "", statement: "" });
  void search();
}

onMounted(async () => {
  try {
    [users.value, connections.value] = await Promise.all([accessAdmin.users(), listConnections()]);
  } catch (e) {
    error.value = errorText(e);
  }
  await search();
});
</script>

<template>
  <div class="space-y-4" data-testid="audit-log">
    <div class="space-y-1">
      <Label class="text-base">{{ t("audit.title") }}</Label>
      <p class="text-sm text-muted-foreground">{{ t("audit.description") }}</p>
    </div>

    <form class="space-y-2 rounded-md border border-border/60 p-3" data-testid="audit-filters" @submit.prevent="search()">
      <div class="grid gap-2 sm:grid-cols-2">
        <select v-model="filters.userId" :class="selectClass" :aria-label="t('audit.user')" data-testid="audit-user">
          <option value="">{{ t("audit.anyUser") }}</option>
          <option v-for="user in users" :key="user.id" :value="user.id">{{ user.username }}</option>
        </select>
        <select v-model="filters.connectionId" :class="selectClass" :aria-label="t('access.connection')" data-testid="audit-connection">
          <option value="">{{ t("access.allConnections") }}</option>
          <option v-for="connection in connections" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
        </select>
        <select v-model="filters.event" :class="selectClass" :aria-label="t('audit.event')" data-testid="audit-event">
          <option value="">{{ t("audit.anyEvent") }}</option>
          <option v-for="event in AUDIT_EVENTS" :key="event" :value="event">{{ eventLabel(event) }}</option>
        </select>
        <select v-model="filters.decision" :class="selectClass" :aria-label="t('audit.decision')" data-testid="audit-decision">
          <option value="">{{ t("audit.anyDecision") }}</option>
          <option value="allow">{{ t("audit.allowed") }}</option>
          <option value="deny">{{ t("audit.denied") }}</option>
        </select>
        <label class="space-y-1 text-xs text-muted-foreground">
          {{ t("audit.from") }}
          <Input v-model="filters.from" type="date" class="h-9" data-testid="audit-from" />
        </label>
        <label class="space-y-1 text-xs text-muted-foreground">
          {{ t("audit.to") }}
          <Input v-model="filters.to" type="date" class="h-9" data-testid="audit-to" />
        </label>
      </div>
      <label class="block space-y-1 text-xs text-muted-foreground">
        {{ t("audit.statementSearch") }}
        <textarea v-model="filters.statement" rows="2" class="w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs text-foreground" :placeholder="t('audit.statementSearchHint')" data-testid="audit-statement" />
      </label>
      <div class="flex flex-wrap items-center justify-end gap-2">
        <label class="mr-auto flex items-center gap-2 text-xs text-muted-foreground">
          <input v-model="includeStatements" type="checkbox" data-testid="audit-include-statements" />
          {{ t("audit.includeStatements") }}
        </label>
        <Button type="button" variant="ghost" size="sm" @click="resetFilters">{{ t("audit.clear") }}</Button>
        <Button type="button" variant="outline" size="sm" :disabled="exporting" data-testid="audit-export" @click="exportCsv">
          <Loader2 v-if="exporting" class="mr-1 h-4 w-4 animate-spin" />
          <Download v-else class="mr-1 h-4 w-4" />
          {{ t("audit.export") }}
        </Button>
        <Button type="submit" size="sm" :disabled="loading" data-testid="audit-search">
          <Search class="mr-1 h-4 w-4" />
          {{ t("audit.search") }}
        </Button>
      </div>
    </form>

    <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
    <p v-if="notice" class="text-sm text-muted-foreground">{{ notice }}</p>
    <p v-if="droppedEvents" class="text-xs text-destructive">{{ t("audit.droppedEvents", { count: droppedEvents }) }}</p>

    <div class="overflow-hidden rounded-md border border-border/60">
      <p v-if="!entries.length && !loading" class="px-3 py-3 text-sm text-muted-foreground">{{ t("audit.empty") }}</p>
      <div v-for="entry in entries" :key="entry.id" class="border-b border-border/60 last:border-b-0" data-testid="audit-entry">
        <button type="button" class="flex w-full items-start gap-2 px-3 py-2 text-left hover:bg-muted/40" @click="toggle(entry)">
          <ChevronDown v-if="expanded[entry.id]" class="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
          <ChevronRight v-else class="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
          <div class="min-w-0 flex-1">
            <p class="truncate text-sm">
              <span class="font-medium">{{ eventLabel(entry.event) }}</span>
              <span class="text-muted-foreground"> · {{ actorLabel(entry) }}</span>
              <span v-if="target(entry)" class="text-muted-foreground"> · {{ target(entry) }}</span>
            </p>
            <p class="truncate text-xs text-muted-foreground">
              {{ formatTime(entry.ts) }}
              <span v-if="entry.operations.length" class="font-mono"> · {{ entry.operations.join(" · ") }}</span>
            </p>
          </div>
          <span v-if="entry.decision" :class="['shrink-0 rounded px-1.5 py-0.5 text-xs font-medium', entry.decision === 'deny' ? 'bg-destructive/15 text-destructive' : 'bg-green-500/15 text-green-600']">
            {{ entry.decision === "deny" ? t("audit.denied") : t("audit.allowed") }}
          </span>
        </button>
        <div v-if="expanded[entry.id]" class="space-y-2 bg-muted/30 px-9 py-2 text-xs" data-testid="audit-entry-detail">
          <dl class="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
            <template v-if="entry.reason">
              <dt class="text-muted-foreground">{{ t("audit.reason") }}</dt>
              <dd class="break-words">{{ entry.reason }}</dd>
            </template>
            <template v-if="entry.ip">
              <dt class="text-muted-foreground">{{ t("audit.ip") }}</dt>
              <dd class="font-mono">{{ entry.ip }}</dd>
            </template>
            <template v-if="entry.session_ref">
              <dt class="text-muted-foreground">{{ t("audit.session") }}</dt>
              <dd class="font-mono">{{ entry.session_ref }}</dd>
            </template>
            <dt class="text-muted-foreground">{{ t("audit.eventId") }}</dt>
            <dd class="font-mono">{{ entry.event_id }}</dd>
          </dl>
          <pre v-if="entry.detail" class="overflow-x-auto rounded bg-background p-2 font-mono">{{ JSON.stringify(entry.detail, null, 2) }}</pre>
          <div v-if="entry.has_statement" class="space-y-1">
            <pre v-if="revealed[entry.event_id] !== undefined" class="overflow-x-auto whitespace-pre-wrap rounded bg-background p-2 font-mono" data-testid="audit-statement-text">{{ revealed[entry.event_id] }}</pre>
            <div v-else class="flex items-center gap-2">
              <span class="text-muted-foreground">{{ t("audit.statementEncrypted") }}</span>
              <Button size="sm" variant="outline" class="h-7" :disabled="revealing === entry.event_id" data-testid="audit-reveal" @click="reveal(entry)">
                {{ t("audit.reveal") }}
              </Button>
            </div>
            <p class="text-muted-foreground">{{ t("audit.revealHint") }}</p>
          </div>
        </div>
      </div>
    </div>
    <div v-if="loading" class="flex items-center gap-2 text-sm text-muted-foreground">
      <Loader2 class="h-4 w-4 animate-spin" />
      {{ t("auth.processing") }}
    </div>
    <div v-else-if="nextBeforeId" class="flex justify-center">
      <Button variant="ghost" size="sm" data-testid="audit-more" @click="search(true)">{{ t("audit.loadMore") }}</Button>
    </div>
  </div>
</template>
