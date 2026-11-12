<script setup lang="ts">
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Trash2, Users } from "@lucide/vue";
import { translateBackendError } from "@/i18n/backend-errors";
import { accessAdmin, type ManagedUser, type UserGroup } from "@/lib/auth/accessAdmin";

const props = defineProps<{ users: ManagedUser[]; groups: UserGroup[] }>();
const emit = defineEmits<{ changed: [] }>();
const { t } = useI18n();

const newName = ref("");
const busy = ref(false);
const error = ref("");
const editingId = ref("");
const selectedMembers = ref<string[]>([]);

async function run(action: () => Promise<unknown>) {
  busy.value = true;
  error.value = "";
  try {
    await action();
    emit("changed");
  } catch (e) {
    error.value = translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("users.actionFailed");
  } finally {
    busy.value = false;
  }
}

function createGroup() {
  const name = newName.value.trim();
  if (!name) return;
  void run(async () => {
    await accessAdmin.createGroup(name, null);
    newName.value = "";
  });
}

function editMembers(group: UserGroup) {
  editingId.value = editingId.value === group.id ? "" : group.id;
  selectedMembers.value = [...group.member_ids];
}

function saveMembers(group: UserGroup) {
  void run(async () => {
    await accessAdmin.setGroupMembers(group.id, selectedMembers.value);
    editingId.value = "";
  });
}

function deleteGroup(group: UserGroup) {
  if (!window.confirm(t("access.confirmDeleteGroup", { name: group.name }))) return;
  void run(() => accessAdmin.deleteGroup(group.id));
}

function memberNames(group: UserGroup): string {
  const names = group.member_ids.map((id) => props.users.find((user) => user.id === id)?.username).filter(Boolean);
  return names.length ? names.join(", ") : t("access.noMembers");
}
</script>

<template>
  <div class="space-y-3" data-testid="access-groups">
    <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
    <div class="overflow-hidden rounded-md border border-border/60">
      <p v-if="!groups.length" class="px-3 py-3 text-sm text-muted-foreground">{{ t("access.noGroups") }}</p>
      <div v-for="group in groups" :key="group.id" class="border-b border-border/60 px-3 py-2 last:border-b-0" data-testid="access-group">
        <div class="flex items-center gap-2">
          <div class="min-w-0 flex-1">
            <p class="truncate text-sm font-medium">{{ group.name }}</p>
            <p class="truncate text-xs text-muted-foreground">{{ memberNames(group) }}</p>
          </div>
          <Button variant="ghost" size="icon" class="h-8 w-8" :title="t('access.editMembers')" :disabled="busy" @click="editMembers(group)">
            <Users class="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" class="h-8 w-8 text-destructive hover:text-destructive" :title="t('users.delete')" :disabled="busy" @click="deleteGroup(group)">
            <Trash2 class="h-4 w-4" />
          </Button>
        </div>
        <div v-if="editingId === group.id" class="mt-2 space-y-2 rounded-md bg-muted/40 p-2">
          <label v-for="user in users" :key="user.id" class="flex items-center gap-2 text-sm">
            <input v-model="selectedMembers" type="checkbox" :value="user.id" />
            {{ user.display_name || user.username }}
            <span class="text-xs text-muted-foreground">{{ user.username }}</span>
          </label>
          <div class="flex justify-end">
            <Button size="sm" :disabled="busy" @click="saveMembers(group)">{{ t("access.save") }}</Button>
          </div>
        </div>
      </div>
    </div>
    <form class="flex gap-2" @submit.prevent="createGroup">
      <Input v-model="newName" :placeholder="t('access.newGroup')" class="h-9" data-testid="new-group-name" />
      <Button type="submit" size="sm" :disabled="busy || !newName.trim()">{{ t("access.create") }}</Button>
    </form>
  </div>
</template>
