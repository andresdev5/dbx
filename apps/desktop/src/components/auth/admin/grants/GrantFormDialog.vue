<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Loader2 } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { accessAdmin, endOfDay, OPERATIONS, type Grant, type GrantDraft, type GrantSubject, type Operation } from "@/lib/auth/accessAdmin";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { checkboxClass, dateInputValue, fieldLabelClass, selectClass, useAdminText } from "../shared/adminUi";

type SubjectKind = GrantSubject["kind"];

const props = defineProps<{ open: boolean; grant?: Grant | null; duplicate?: boolean; lockedSubject?: GrantSubject; presetConnection?: string }>();
const emit = defineEmits<{ "update:open": [open: boolean]; saved: [grant: Grant] }>();
const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();

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
const busy = ref(false);
const error = ref("");
const now = ref(Date.now());

const editingId = computed(() => (props.grant && !props.duplicate ? props.grant.id : ""));
const today = computed(() => dateInputValue(now.value));
const expiryInPast = computed(() => {
  const expiresAt = endOfDay(expiresOn.value);
  return expiresAt !== null && expiresAt <= now.value;
});

const subjectOptions = computed(() => {
  if (subjectKind.value === "user") return directory.users.value.map((user) => ({ id: user.id, label: user.display_name ? `${user.display_name} (${user.username})` : user.username }));
  if (subjectKind.value === "group") return directory.groups.value.map((group) => ({ id: group.id, label: group.name }));
  return [];
});

const canSave = computed(() => {
  if (busy.value) return false;
  if (subjectKind.value !== "system" && !subjectId.value) return false;
  if (scopeKind.value === "resource" && !connectionId.value) return false;
  if (scopeKind.value === "resource" && (schema.value.trim() || table.value.trim()) && !database.value.trim()) return false;
  if (expiryInPast.value) return false;
  if (mode.value === "role") return Boolean(roleId.value);
  return operations.value.length > 0;
});

function roleLabel(id: string): string {
  const role = directory.roles.value.find((candidate) => candidate.id === id);
  if (!role) return id;
  return role.builtin ? t(`access.builtinRoles.${role.name}`) : role.name;
}

function applySubject(subject: GrantSubject) {
  subjectKind.value = subject.kind;
  subjectId.value = subject.kind === "system" ? "" : subject.id;
}

function reset() {
  now.value = Date.now();
  error.value = "";
  const grant = props.grant;
  if (props.lockedSubject) applySubject(props.lockedSubject);
  else if (grant) applySubject(grant.subject);
  else applySubject({ kind: "user", id: "" });
  if (grant?.scope.kind === "resource") {
    scopeKind.value = "resource";
    connectionId.value = grant.scope.value.connectionId;
    database.value = grant.scope.value.database ?? "";
    schema.value = grant.scope.value.schema ?? "";
    table.value = grant.scope.value.table ?? "";
  } else {
    scopeKind.value = grant ? "all" : "resource";
    connectionId.value = grant ? "" : (props.presetConnection ?? "");
    database.value = "";
    schema.value = "";
    table.value = "";
  }
  effect.value = grant?.effect ?? "allow";
  mode.value = grant && !grant.role_id ? "operations" : "role";
  roleId.value = grant?.role_id ?? "builtin:reader";
  operations.value = grant?.operations ? [...grant.operations] : ["SELECT"];
  expiresOn.value = dateInputValue(grant?.expires_at ?? null);
  note.value = grant?.note ?? "";
}

watch(
  () => props.open,
  (open) => {
    if (open) reset();
  },
  { immediate: true },
);

function changeSubjectKind(kind: SubjectKind) {
  subjectKind.value = kind;
  subjectId.value = "";
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

async function submit() {
  if (!canSave.value) return;
  busy.value = true;
  error.value = "";
  try {
    const saved = await accessAdmin.saveGrant(draft());
    emit("saved", saved);
    emit("update:open", false);
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <Dialog :open="open" @update:open="(value: boolean) => emit('update:open', value)">
    <DialogContent class="sm:max-w-2xl" data-testid="grant-form-dialog">
      <DialogHeader>
        <DialogTitle>{{ editingId ? t("access.editGrant") : t("access.newGrant") }}</DialogTitle>
      </DialogHeader>
      <form id="admin-grant-form" class="max-h-[min(70vh,640px)] space-y-5 overflow-y-auto pr-1" data-testid="grant-form" @submit.prevent="submit">
        <fieldset class="space-y-3">
          <legend class="mb-2 text-sm font-semibold">{{ t("adminConsole.grants.form.sections.subject") }}</legend>
          <div class="grid gap-3 sm:grid-cols-2">
            <label :class="['block', fieldLabelClass]">
              {{ t("access.subject") }}
              <select :value="subjectKind" :class="selectClass" :disabled="Boolean(lockedSubject)" data-testid="grant-subject-kind" @change="changeSubjectKind(($event.target as HTMLSelectElement).value as SubjectKind)">
                <option value="user">{{ t("access.subjectKindUser") }}</option>
                <option value="group">{{ t("access.subjectKindGroup") }}</option>
                <option value="system">{{ t("access.subjectSystem") }}</option>
              </select>
            </label>
            <label v-if="subjectKind !== 'system'" :class="['block', fieldLabelClass]">
              {{ subjectKind === "user" ? t("access.subjectKindUser") : t("access.subjectKindGroup") }}
              <select v-model="subjectId" :class="selectClass" :disabled="Boolean(lockedSubject)" data-testid="grant-subject">
                <option value="" disabled>{{ t("access.choose") }}</option>
                <option v-for="option in subjectOptions" :key="option.id" :value="option.id">{{ option.label }}</option>
              </select>
            </label>
          </div>
        </fieldset>

        <fieldset class="space-y-3 border-t border-border/60 pt-4">
          <legend class="mb-2 text-sm font-semibold">{{ t("adminConsole.grants.form.sections.scope") }}</legend>
          <div class="grid gap-3 sm:grid-cols-2">
            <label :class="['block', fieldLabelClass]">
              {{ t("access.scope") }}
              <select v-model="scopeKind" :class="selectClass" data-testid="grant-scope">
                <option value="resource">{{ t("access.scopeResource") }}</option>
                <option value="all">{{ t("access.scopeAll") }}</option>
              </select>
            </label>
            <label v-if="scopeKind === 'resource'" :class="['block', fieldLabelClass]">
              {{ t("access.connection") }}
              <select v-model="connectionId" :class="selectClass" data-testid="grant-connection">
                <option value="" disabled>{{ t("access.choose") }}</option>
                <option v-for="connection in directory.connections.value" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
              </select>
            </label>
          </div>
          <template v-if="scopeKind === 'resource'">
            <div class="grid gap-3 sm:grid-cols-3">
              <Input v-model="database" :placeholder="t('access.databaseAny')" data-testid="grant-database" />
              <Input v-model="schema" :placeholder="t('access.schemaAny')" data-testid="grant-schema" />
              <Input v-model="table" :placeholder="t('access.tableAny')" data-testid="grant-table" />
            </div>
            <p class="text-xs text-muted-foreground">{{ t("access.resourceHint") }}</p>
          </template>
        </fieldset>

        <fieldset class="space-y-3 border-t border-border/60 pt-4">
          <legend class="mb-2 text-sm font-semibold">{{ t("adminConsole.grants.form.sections.permissions") }}</legend>
          <div class="grid gap-3 sm:grid-cols-2">
            <label :class="['block', fieldLabelClass]">
              {{ t("access.effect") }}
              <select v-model="effect" :class="selectClass" data-testid="grant-effect">
                <option value="allow">{{ t("access.allow") }}</option>
                <option value="deny">{{ t("access.deny") }}</option>
              </select>
            </label>
            <label :class="['block', fieldLabelClass]">
              {{ t("access.permissions") }}
              <select v-model="mode" :class="selectClass" data-testid="grant-mode">
                <option value="role">{{ t("access.useRole") }}</option>
                <option value="operations">{{ t("access.useOperations") }}</option>
              </select>
            </label>
          </div>
          <template v-if="mode === 'role'">
            <select v-model="roleId" :class="selectClass" :aria-label="t('access.useRole')" data-testid="grant-role">
              <option v-for="role in directory.roles.value" :key="role.id" :value="role.id">{{ roleLabel(role.id) }} — {{ role.operations.join(", ") }}</option>
            </select>
            <p class="text-xs text-muted-foreground">{{ t("adminConsole.grants.form.roleHint") }}</p>
          </template>
          <div v-else class="grid grid-cols-2 gap-2 rounded-md border border-border/60 p-3 sm:grid-cols-4" data-testid="grant-operations">
            <label v-for="operation in OPERATIONS" :key="operation" class="flex items-center gap-2 font-mono text-xs">
              <input v-model="operations" type="checkbox" :class="checkboxClass" :value="operation" />
              {{ operation }}
            </label>
          </div>
          <p v-if="effect === 'deny'" class="rounded-md bg-destructive/5 px-3 py-2 text-xs text-destructive" data-testid="grant-deny-hint">{{ t("access.denyHint") }}</p>
        </fieldset>

        <fieldset class="space-y-3 border-t border-border/60 pt-4">
          <legend class="mb-2 text-sm font-semibold">{{ t("adminConsole.grants.form.sections.validity") }}</legend>
          <div class="grid gap-3 sm:grid-cols-2">
            <label :class="['block', fieldLabelClass]">
              {{ t("access.expires") }}
              <Input v-model="expiresOn" type="date" :min="today" data-testid="grant-expires" />
              <span v-if="expiryInPast" class="block font-normal text-destructive" data-testid="grant-expiry-past">{{ t("access.expiryInPast") }}</span>
            </label>
            <label :class="['block', fieldLabelClass]">
              {{ t("access.note") }}
              <Input v-model="note" maxlength="500" data-testid="grant-note" />
            </label>
          </div>
        </fieldset>
        <p v-if="error" class="text-sm text-destructive" data-testid="grant-form-error">{{ error }}</p>
      </form>
      <DialogFooter>
        <Button variant="outline" @click="emit('update:open', false)">{{ t("common.cancel") }}</Button>
        <Button type="submit" form="admin-grant-form" :disabled="!canSave" data-testid="grant-save">
          <Loader2 v-if="busy" class="animate-spin" />
          {{ editingId ? t("adminConsole.grants.form.save") : t("adminConsole.grants.form.create") }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
