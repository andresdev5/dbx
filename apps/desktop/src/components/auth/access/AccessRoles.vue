<script setup lang="ts">
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Pencil, Trash2 } from "@lucide/vue";
import { translateBackendError } from "@/i18n/backend-errors";
import { accessAdmin, OPERATIONS, type DataRole, type Operation } from "@/lib/auth/accessAdmin";

defineProps<{ roles: DataRole[] }>();
const emit = defineEmits<{ changed: [] }>();
const { t } = useI18n();

const editingId = ref("");
const name = ref("");
const operations = ref<Operation[]>([]);
const busy = ref(false);
const error = ref("");

function roleLabel(role: DataRole): string {
  return role.builtin ? t(`access.builtinRoles.${role.name}`) : role.name;
}

function startEdit(role?: DataRole) {
  editingId.value = role?.id ?? "";
  name.value = role?.name ?? "";
  operations.value = role ? [...role.operations] : ["SELECT"];
}

async function save() {
  busy.value = true;
  error.value = "";
  try {
    if (editingId.value) {
      await accessAdmin.updateRole(editingId.value, name.value.trim(), operations.value, null);
    } else {
      await accessAdmin.createRole(name.value.trim(), operations.value, null);
    }
    startEdit();
    emit("changed");
  } catch (e) {
    error.value = translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("users.actionFailed");
  } finally {
    busy.value = false;
  }
}

async function remove(role: DataRole) {
  if (!window.confirm(t("access.confirmDeleteRole", { name: role.name }))) return;
  busy.value = true;
  error.value = "";
  try {
    await accessAdmin.deleteRole(role.id);
    emit("changed");
  } catch (e) {
    error.value = translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("users.actionFailed");
  } finally {
    busy.value = false;
  }
}

startEdit();
</script>

<template>
  <div class="space-y-3" data-testid="access-roles">
    <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
    <div class="overflow-hidden rounded-md border border-border/60">
      <div v-for="role in roles" :key="role.id" class="flex items-center gap-2 border-b border-border/60 px-3 py-2 last:border-b-0" data-testid="access-role">
        <div class="min-w-0 flex-1">
          <p class="truncate text-sm font-medium">
            {{ roleLabel(role) }}
            <span v-if="role.builtin" class="text-xs font-normal text-muted-foreground">{{ t("access.builtin") }}</span>
          </p>
          <p class="truncate font-mono text-xs text-muted-foreground">{{ role.operations.join(" · ") }}</p>
        </div>
        <template v-if="!role.builtin">
          <Button variant="ghost" size="icon" class="h-8 w-8" :title="t('access.edit')" :disabled="busy" @click="startEdit(role)">
            <Pencil class="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" class="h-8 w-8 text-destructive hover:text-destructive" :title="t('users.delete')" :disabled="busy" @click="remove(role)">
            <Trash2 class="h-4 w-4" />
          </Button>
        </template>
      </div>
    </div>
    <form class="space-y-2 rounded-md border border-border/60 p-3" data-testid="role-form" @submit.prevent="save">
      <p class="text-sm font-medium">{{ editingId ? t("access.editRole") : t("access.newRole") }}</p>
      <Input v-model="name" :placeholder="t('access.roleName')" class="h-9" />
      <div class="grid grid-cols-2 gap-1 sm:grid-cols-4">
        <label v-for="operation in OPERATIONS" :key="operation" class="flex items-center gap-2 font-mono text-xs">
          <input v-model="operations" type="checkbox" :value="operation" />
          {{ operation }}
        </label>
      </div>
      <div class="flex justify-end gap-2">
        <Button v-if="editingId" type="button" variant="ghost" size="sm" @click="startEdit()">{{ t("common.cancel") }}</Button>
        <Button type="submit" size="sm" :disabled="busy || !name.trim() || !operations.length">{{ t("access.save") }}</Button>
      </div>
    </form>
  </div>
</template>
