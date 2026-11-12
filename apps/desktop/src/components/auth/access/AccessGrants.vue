<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Pencil, Trash2 } from "@lucide/vue";
import { translateBackendError } from "@/i18n/backend-errors";
import { accessAdmin, describeResource, endOfDay, OPERATIONS, type ConnectionSummary, type DataRole, type Grant, type GrantDraft, type GrantSubject, type ManagedUser, type Operation, type UserGroup } from "@/lib/auth/accessAdmin";

const props = defineProps<{ users: ManagedUser[]; groups: UserGroup[]; roles: DataRole[]; connections: ConnectionSummary[] }>();
const { t } = useI18n();

type SubjectKind = GrantSubject["kind"];

const grants = ref<Grant[]>([]);
const busy = ref(false);
const error = ref("");
const filterConnection = ref("");

const editingId = ref("");
const subjectKind = ref<SubjectKind>("user");
const subjectId = ref("");
const scopeKind = ref<"all" | "resource">("resource");
const connectionId = ref("");
const database = ref("");
const schema = ref("");
const table = ref("");
const effect = ref<"allow" | "deny">("allow");
const mode = ref<"role" | "operations">("role");
const roleId = ref("builtin:reader");
const operations = ref<Operation[]>(["SELECT"]);
const expiresOn = ref("");
const note = ref("");

const selectClass = "h-9 w-full rounded-md border border-input bg-background px-2 text-sm";

const visibleGrants = computed(() => grants.value.filter((grant) => !filterConnection.value || grant.scope.kind !== "resource" || grant.scope.value.connectionId === filterConnection.value));

const subjectOptions = computed(() => {
  if (subjectKind.value === "user") return props.users.map((user) => ({ id: user.id, label: user.display_name ? `${user.display_name} (${user.username})` : user.username }));
  if (subjectKind.value === "group") return props.groups.map((group) => ({ id: group.id, label: group.name }));
  return [];
});

const canSave = computed(() => {
  if (subjectKind.value !== "system" && !subjectId.value) return false;
  if (scopeKind.value === "resource" && !connectionId.value) return false;
  if (scopeKind.value === "resource" && (schema.value.trim() || table.value.trim()) && !database.value.trim()) return false;
  if (mode.value === "role") return Boolean(roleId.value);
  return operations.value.length > 0;
});

function errorText(e: unknown): string {
  return translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("users.actionFailed");
}

async function load() {
  try {
    grants.value = await accessAdmin.grants();
  } catch (e) {
    error.value = errorText(e);
  }
}

function subjectLabel(subject: GrantSubject): string {
  if (subject.kind === "system") return t("access.subjectSystem");
  if (subject.kind === "user") {
    const user = props.users.find((candidate) => candidate.id === subject.id);
    return t("access.subjectUser", { name: user?.username ?? subject.id });
  }
  const group = props.groups.find((candidate) => candidate.id === subject.id);
  return t("access.subjectGroup", { name: group?.name ?? subject.id });
}

function scopeLabel(grant: Grant): string {
  if (grant.scope.kind === "all") return t("access.scopeAll");
  if (grant.scope.kind === "connection_group") return t("access.scopeConnectionGroup", { name: grant.scope.value });
  return describeResource(grant.scope.value, props.connections);
}

function roleName(id: string): string {
  const role = props.roles.find((candidate) => candidate.id === id);
  if (!role) return id;
  return role.builtin ? t(`access.builtinRoles.${role.name}`) : role.name;
}

function grantOperations(grant: Grant): string {
  if (grant.role_id) return roleName(grant.role_id);
  return (grant.operations ?? []).join(" · ");
}

function expiryLabel(grant: Grant): string {
  return grant.expires_at ? t("access.expiresOn", { date: new Date(grant.expires_at).toLocaleDateString() }) : "";
}

function dateInput(millis: number | null): string {
  if (!millis) return "";
  const date = new Date(millis);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function resetForm() {
  editingId.value = "";
  subjectKind.value = "user";
  subjectId.value = "";
  scopeKind.value = "resource";
  connectionId.value = filterConnection.value;
  database.value = "";
  schema.value = "";
  table.value = "";
  effect.value = "allow";
  mode.value = "role";
  roleId.value = "builtin:reader";
  operations.value = ["SELECT"];
  expiresOn.value = "";
  note.value = "";
}

function edit(grant: Grant) {
  editingId.value = grant.id;
  subjectKind.value = grant.subject.kind;
  subjectId.value = grant.subject.kind === "system" ? "" : grant.subject.id;
  if (grant.scope.kind === "resource") {
    scopeKind.value = "resource";
    connectionId.value = grant.scope.value.connectionId;
    database.value = grant.scope.value.database ?? "";
    schema.value = grant.scope.value.schema ?? "";
    table.value = grant.scope.value.table ?? "";
  } else {
    scopeKind.value = "all";
    connectionId.value = "";
    database.value = "";
    schema.value = "";
    table.value = "";
  }
  effect.value = grant.effect;
  mode.value = grant.role_id ? "role" : "operations";
  roleId.value = grant.role_id ?? "builtin:reader";
  operations.value = grant.operations ? [...grant.operations] : ["SELECT"];
  expiresOn.value = dateInput(grant.expires_at);
  note.value = grant.note ?? "";
}

function draft(): GrantDraft {
  const subject: GrantSubject = subjectKind.value === "system" ? { kind: "system" } : { kind: subjectKind.value, id: subjectId.value };
  const optional = (value: string) => value.trim() || undefined;
  return {
    id: editingId.value || undefined,
    subject,
    scope: scopeKind.value === "all" ? { kind: "all" } : { kind: "resource", value: { connectionId: connectionId.value, database: optional(database.value), schema: optional(schema.value), table: optional(table.value) } },
    effect: effect.value,
    operations: mode.value === "operations" ? operations.value : null,
    role_id: mode.value === "role" ? roleId.value : null,
    expires_at: endOfDay(expiresOn.value),
    note: note.value.trim() || null,
  };
}

async function save() {
  busy.value = true;
  error.value = "";
  try {
    await accessAdmin.saveGrant(draft());
    resetForm();
    await load();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}

async function remove(grant: Grant) {
  if (!window.confirm(t("access.confirmDeleteGrant"))) return;
  busy.value = true;
  error.value = "";
  try {
    await accessAdmin.deleteGrant(grant.id);
    if (editingId.value === grant.id) resetForm();
    await load();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}

function changeSubjectKind(kind: SubjectKind) {
  subjectKind.value = kind;
  subjectId.value = "";
}

onMounted(() => {
  resetForm();
  void load();
});
</script>

<template>
  <div class="space-y-3" data-testid="access-grants">
    <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
    <div class="flex items-center gap-2">
      <span class="text-sm text-muted-foreground">{{ t("access.filterConnection") }}</span>
      <select v-model="filterConnection" class="h-8 rounded-md border border-input bg-background px-2 text-sm" data-testid="grant-filter">
        <option value="">{{ t("access.allConnections") }}</option>
        <option v-for="connection in connections" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
      </select>
    </div>
    <div class="overflow-hidden rounded-md border border-border/60">
      <p v-if="!visibleGrants.length" class="px-3 py-3 text-sm text-muted-foreground">{{ t("access.noGrants") }}</p>
      <div v-for="grant in visibleGrants" :key="grant.id" class="flex items-center gap-2 border-b border-border/60 px-3 py-2 last:border-b-0" data-testid="access-grant">
        <span :class="['rounded px-1.5 py-0.5 text-xs font-medium', grant.effect === 'deny' ? 'bg-destructive/15 text-destructive' : 'bg-green-500/15 text-green-600']">
          {{ grant.effect === "deny" ? t("access.deny") : t("access.allow") }}
        </span>
        <div class="min-w-0 flex-1">
          <p class="truncate text-sm">
            <span class="font-medium">{{ subjectLabel(grant.subject) }}</span>
            <span class="text-muted-foreground"> · {{ scopeLabel(grant) }}</span>
          </p>
          <p class="truncate text-xs text-muted-foreground">
            <span class="font-mono">{{ grantOperations(grant) }}</span>
            <span v-if="grant.expires_at"> · {{ expiryLabel(grant) }}</span>
            <span v-if="grant.note"> · {{ grant.note }}</span>
          </p>
        </div>
        <Button variant="ghost" size="icon" class="h-8 w-8" :title="t('access.edit')" :disabled="busy" @click="edit(grant)">
          <Pencil class="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="icon" class="h-8 w-8 text-destructive hover:text-destructive" :title="t('users.delete')" :disabled="busy" @click="remove(grant)">
          <Trash2 class="h-4 w-4" />
        </Button>
      </div>
    </div>

    <form class="space-y-3 rounded-md border border-border/60 p-3" data-testid="grant-form" @submit.prevent="save">
      <p class="text-sm font-medium">{{ editingId ? t("access.editGrant") : t("access.newGrant") }}</p>
      <div class="grid gap-2 sm:grid-cols-2">
        <label class="space-y-1 text-xs text-muted-foreground">
          {{ t("access.subject") }}
          <select :value="subjectKind" :class="selectClass" data-testid="grant-subject-kind" @change="changeSubjectKind(($event.target as HTMLSelectElement).value as SubjectKind)">
            <option value="user">{{ t("access.subjectKindUser") }}</option>
            <option value="group">{{ t("access.subjectKindGroup") }}</option>
            <option value="system">{{ t("access.subjectSystem") }}</option>
          </select>
        </label>
        <label v-if="subjectKind !== 'system'" class="space-y-1 text-xs text-muted-foreground">
          {{ subjectKind === "user" ? t("access.subjectKindUser") : t("access.subjectKindGroup") }}
          <select v-model="subjectId" :class="selectClass" data-testid="grant-subject">
            <option value="" disabled>{{ t("access.choose") }}</option>
            <option v-for="option in subjectOptions" :key="option.id" :value="option.id">{{ option.label }}</option>
          </select>
        </label>
      </div>

      <div class="grid gap-2 sm:grid-cols-2">
        <label class="space-y-1 text-xs text-muted-foreground">
          {{ t("access.scope") }}
          <select v-model="scopeKind" :class="selectClass" data-testid="grant-scope">
            <option value="resource">{{ t("access.scopeResource") }}</option>
            <option value="all">{{ t("access.scopeAll") }}</option>
          </select>
        </label>
        <label v-if="scopeKind === 'resource'" class="space-y-1 text-xs text-muted-foreground">
          {{ t("access.connection") }}
          <select v-model="connectionId" :class="selectClass" data-testid="grant-connection">
            <option value="" disabled>{{ t("access.choose") }}</option>
            <option v-for="connection in connections" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
          </select>
        </label>
      </div>
      <div v-if="scopeKind === 'resource'" class="grid gap-2 sm:grid-cols-3">
        <Input v-model="database" :placeholder="t('access.databaseAny')" class="h-9" data-testid="grant-database" />
        <Input v-model="schema" :placeholder="t('access.schemaAny')" class="h-9" />
        <Input v-model="table" :placeholder="t('access.tableAny')" class="h-9" />
      </div>
      <p v-if="scopeKind === 'resource'" class="text-xs text-muted-foreground">{{ t("access.resourceHint") }}</p>

      <div class="grid gap-2 sm:grid-cols-2">
        <label class="space-y-1 text-xs text-muted-foreground">
          {{ t("access.effect") }}
          <select v-model="effect" :class="selectClass" data-testid="grant-effect">
            <option value="allow">{{ t("access.allow") }}</option>
            <option value="deny">{{ t("access.deny") }}</option>
          </select>
        </label>
        <label class="space-y-1 text-xs text-muted-foreground">
          {{ t("access.permissions") }}
          <select v-model="mode" :class="selectClass" data-testid="grant-mode">
            <option value="role">{{ t("access.useRole") }}</option>
            <option value="operations">{{ t("access.useOperations") }}</option>
          </select>
        </label>
      </div>
      <select v-if="mode === 'role'" v-model="roleId" :class="selectClass" data-testid="grant-role">
        <option v-for="role in roles" :key="role.id" :value="role.id">{{ roleName(role.id) }} — {{ role.operations.join(", ") }}</option>
      </select>
      <div v-else class="grid grid-cols-2 gap-1 sm:grid-cols-4" data-testid="grant-operations">
        <label v-for="operation in OPERATIONS" :key="operation" class="flex items-center gap-2 font-mono text-xs">
          <input v-model="operations" type="checkbox" :value="operation" />
          {{ operation }}
        </label>
      </div>
      <p v-if="effect === 'deny'" class="text-xs text-muted-foreground">{{ t("access.denyHint") }}</p>

      <div class="grid gap-2 sm:grid-cols-2">
        <label class="space-y-1 text-xs text-muted-foreground">
          {{ t("access.expires") }}
          <Input v-model="expiresOn" type="date" class="h-9" />
        </label>
        <label class="space-y-1 text-xs text-muted-foreground">
          {{ t("access.note") }}
          <Input v-model="note" class="h-9" maxlength="500" />
        </label>
      </div>

      <div class="flex justify-end gap-2">
        <Button v-if="editingId" type="button" variant="ghost" size="sm" @click="resetForm">{{ t("common.cancel") }}</Button>
        <Button type="submit" size="sm" :disabled="busy || !canSave" data-testid="grant-save">{{ t("access.save") }}</Button>
      </div>
    </form>
  </div>
</template>
