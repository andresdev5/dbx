<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Loader2 } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { accessAdmin, OPERATIONS, type DataRole, type Operation } from "@/lib/auth/accessAdmin";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { checkboxClass, fieldLabelClass, useAdminText } from "../shared/adminUi";
import { OPERATION_GROUPS } from "./roleOperations";

export interface RoleDraftSource {
  role: DataRole | null;
  duplicate?: boolean;
}

const props = defineProps<{ open: boolean; source: RoleDraftSource }>();
const emit = defineEmits<{ "update:open": [open: boolean]; saved: [] }>();
const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();

const name = ref("");
const description = ref("");
const operations = ref<Operation[]>([]);
const busy = ref(false);
const error = ref("");

const editingId = computed(() => (props.source.role && !props.source.duplicate ? props.source.role.id : ""));
const canSubmit = computed(() => !busy.value && name.value.trim().length > 0 && operations.value.length > 0);
const title = computed(() => (editingId.value ? t("adminConsole.roles.editRole") : props.source.duplicate ? t("adminConsole.roles.duplicateRole") : t("adminConsole.roles.newRole")));

function roleLabel(role: DataRole): string {
  return role.builtin ? t(`access.builtinRoles.${role.name}`) : role.name;
}

watch(
  () => props.open,
  (open) => {
    if (!open) return;
    const role = props.source.role;
    name.value = role ? (props.source.duplicate ? t("adminConsole.roles.copyName", { name: roleLabel(role) }) : role.name) : "";
    description.value = role?.description ?? "";
    operations.value = role ? [...role.operations] : ["SELECT"];
    error.value = "";
  },
  { immediate: true },
);

function groupState(group: readonly Operation[]): "all" | "some" | "none" {
  const count = group.filter((operation) => operations.value.includes(operation)).length;
  if (count === 0) return "none";
  return count === group.length ? "all" : "some";
}

function setGroup(group: readonly Operation[], selected: boolean) {
  const rest = operations.value.filter((operation) => !group.includes(operation));
  operations.value = selected ? OPERATIONS.filter((operation) => rest.includes(operation) || group.includes(operation)) : rest;
}

function toggle(operation: Operation) {
  operations.value = operations.value.includes(operation) ? operations.value.filter((candidate) => candidate !== operation) : OPERATIONS.filter((candidate) => candidate === operation || operations.value.includes(candidate));
}

async function submit() {
  if (!canSubmit.value) return;
  busy.value = true;
  error.value = "";
  try {
    const trimmedDescription = description.value.trim() || null;
    if (editingId.value) {
      await accessAdmin.updateRole(editingId.value, name.value.trim(), operations.value, trimmedDescription);
    } else {
      await accessAdmin.createRole(name.value.trim(), operations.value, trimmedDescription);
    }
    await directory.refreshRoles();
    emit("saved");
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
    <DialogContent class="sm:max-w-2xl" data-testid="role-form-dialog">
      <DialogHeader>
        <DialogTitle>{{ title }}</DialogTitle>
      </DialogHeader>
      <form id="admin-role-form" class="min-h-0 space-y-4 overflow-y-auto" @submit.prevent="submit">
        <div class="grid gap-4 sm:grid-cols-2">
          <label :class="['block', fieldLabelClass]">
            {{ t("adminConsole.roles.form.name") }}
            <Input v-model="name" :placeholder="t('adminConsole.roles.form.namePlaceholder')" maxlength="80" data-testid="role-form-name" />
          </label>
          <label :class="['block', fieldLabelClass]">
            {{ t("adminConsole.roles.form.description") }}
            <Input v-model="description" :placeholder="t('adminConsole.roles.form.descriptionPlaceholder')" maxlength="500" data-testid="role-form-description" />
          </label>
        </div>
        <div class="space-y-2">
          <div class="flex items-center justify-between">
            <p class="text-xs font-medium text-muted-foreground">{{ t("adminConsole.roles.form.operations") }}</p>
            <span class="text-xs text-muted-foreground">{{ t("adminConsole.roles.form.selectedCount", { count: operations.length }) }}</span>
          </div>
          <div class="grid gap-3 sm:grid-cols-2">
            <fieldset v-for="group in OPERATION_GROUPS" :key="group.key" class="rounded-lg border border-border/70 p-3" :data-testid="`role-form-group-${group.key}`">
              <div class="mb-2 flex items-center justify-between gap-2">
                <legend class="text-sm font-medium">{{ t(`adminConsole.roles.operationGroups.${group.key}`) }}</legend>
                <div class="flex gap-1">
                  <Button type="button" variant="ghost" size="xs" :disabled="groupState(group.operations) === 'all'" :data-testid="`role-form-all-${group.key}`" @click="setGroup(group.operations, true)">{{ t("adminConsole.roles.form.selectAll") }}</Button>
                  <Button type="button" variant="ghost" size="xs" :disabled="groupState(group.operations) === 'none'" @click="setGroup(group.operations, false)">{{ t("adminConsole.roles.form.selectNone") }}</Button>
                </div>
              </div>
              <div class="grid grid-cols-2 gap-1.5">
                <label v-for="operation in group.operations" :key="operation" class="flex items-center gap-2 font-mono text-xs">
                  <input type="checkbox" :class="checkboxClass" :checked="operations.includes(operation)" :data-testid="`role-form-op-${operation}`" @change="toggle(operation)" />
                  {{ operation }}
                </label>
              </div>
            </fieldset>
          </div>
          <p class="text-xs text-muted-foreground">{{ t("adminConsole.roles.form.operationsHint") }}</p>
        </div>
        <p v-if="error" class="text-sm text-destructive" data-testid="role-form-error">{{ error }}</p>
      </form>
      <DialogFooter>
        <Button variant="outline" @click="emit('update:open', false)">{{ t("common.cancel") }}</Button>
        <Button type="submit" form="admin-role-form" :disabled="!canSubmit" data-testid="role-form-submit">
          <Loader2 v-if="busy" class="animate-spin" />
          {{ editingId ? t("adminConsole.roles.form.save") : t("adminConsole.roles.form.create") }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
