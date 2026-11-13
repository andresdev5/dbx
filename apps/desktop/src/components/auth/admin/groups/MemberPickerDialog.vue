<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Loader2, UserPlus } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { accessAdmin, type UserGroup } from "@/lib/auth/accessAdmin";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { normalizeSearch, textMatches } from "@/lib/auth/adminTable";
import AdminAvatar from "../shared/AdminAvatar.vue";
import AdminSearchInput from "../shared/AdminSearchInput.vue";
import { checkboxClass, useAdminText } from "../shared/adminUi";

const props = defineProps<{ open: boolean; group: UserGroup | null }>();
const emit = defineEmits<{ "update:open": [open: boolean]; saved: [] }>();
const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();

const query = ref("");
const selected = ref<string[]>([]);
const busy = ref(false);
const error = ref("");

const candidates = computed(() => {
  const members = new Set(props.group?.member_ids ?? []);
  return directory.users.value.filter((user) => !members.has(user.id)).sort((a, b) => (a.display_name || a.username).localeCompare(b.display_name || b.username));
});

const visible = computed(() => {
  const needle = normalizeSearch(query.value);
  return candidates.value.filter((user) => textMatches(needle, user.username, user.display_name));
});

watch(
  () => props.open,
  (open) => {
    if (!open) return;
    query.value = "";
    selected.value = [];
    error.value = "";
  },
  { immediate: true },
);

function toggle(id: string) {
  selected.value = selected.value.includes(id) ? selected.value.filter((candidate) => candidate !== id) : [...selected.value, id];
}

async function submit() {
  if (!props.group || !selected.value.length) return;
  busy.value = true;
  error.value = "";
  try {
    await accessAdmin.setGroupMembers(props.group.id, [...new Set([...props.group.member_ids, ...selected.value])]);
    await directory.refreshGroups();
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
    <DialogContent class="sm:max-w-lg" data-testid="member-picker">
      <DialogHeader>
        <DialogTitle>{{ t("adminConsole.groups.picker.title", { name: group?.name ?? "" }) }}</DialogTitle>
      </DialogHeader>
      <div class="space-y-3">
        <AdminSearchInput v-model="query" :placeholder="t('adminConsole.groups.picker.search')" />
        <div class="max-h-80 overflow-y-auto rounded-lg border border-border/70">
          <p v-if="!candidates.length" class="px-3 py-6 text-center text-sm text-muted-foreground">{{ t("adminConsole.groups.picker.empty") }}</p>
          <p v-else-if="!visible.length" class="px-3 py-6 text-center text-sm text-muted-foreground">{{ t("adminConsole.groups.picker.noMatch") }}</p>
          <label v-for="user in visible" v-else :key="user.id" class="flex cursor-pointer items-center gap-3 border-b border-border/50 px-3 py-2 last:border-b-0 hover:bg-muted/40" data-testid="member-picker-option">
            <input type="checkbox" :class="checkboxClass" :checked="selected.includes(user.id)" @change="toggle(user.id)" />
            <AdminAvatar :name="user.display_name || user.username" :muted="!user.active" />
            <span class="min-w-0 flex-1">
              <span class="block truncate text-sm font-medium">{{ user.display_name || user.username }}</span>
              <span class="block truncate text-xs text-muted-foreground">{{ user.username }}</span>
            </span>
          </label>
        </div>
        <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
      </div>
      <DialogFooter class="items-center sm:justify-between">
        <span class="text-xs text-muted-foreground">{{ t("adminConsole.groups.picker.selected", { count: selected.length }) }}</span>
        <div class="flex gap-2">
          <Button variant="outline" @click="emit('update:open', false)">{{ t("common.cancel") }}</Button>
          <Button :disabled="busy || !selected.length" data-testid="member-picker-submit" @click="submit">
            <Loader2 v-if="busy" class="animate-spin" />
            <UserPlus v-else />
            {{ t("adminConsole.groups.picker.add", { count: selected.length }) }}
          </Button>
        </div>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
