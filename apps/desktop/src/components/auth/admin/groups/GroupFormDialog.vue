<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Loader2 } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { accessAdmin, type UserGroup } from "@/lib/auth/accessAdmin";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { fieldLabelClass, useAdminText } from "../shared/adminUi";

const props = defineProps<{ open: boolean; group?: UserGroup | null }>();
const emit = defineEmits<{ "update:open": [open: boolean]; saved: [group: UserGroup | null] }>();
const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();

const name = ref("");
const description = ref("");
const busy = ref(false);
const error = ref("");

const editing = computed(() => Boolean(props.group));
const canSubmit = computed(() => !busy.value && name.value.trim().length > 0);

watch(
  () => props.open,
  (open) => {
    if (!open) return;
    name.value = props.group?.name ?? "";
    description.value = props.group?.description ?? "";
    error.value = "";
  },
  { immediate: true },
);

async function submit() {
  if (!canSubmit.value) return;
  busy.value = true;
  error.value = "";
  try {
    const trimmedDescription = description.value.trim() || null;
    let saved: UserGroup | null = null;
    if (props.group) {
      await accessAdmin.updateGroup(props.group.id, name.value.trim(), trimmedDescription);
    } else {
      saved = await accessAdmin.createGroup(name.value.trim(), trimmedDescription);
    }
    await directory.refreshGroups();
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
    <DialogContent class="sm:max-w-lg" data-testid="group-form-dialog">
      <DialogHeader>
        <DialogTitle>{{ editing ? t("adminConsole.groups.editGroup") : t("adminConsole.groups.newGroup") }}</DialogTitle>
      </DialogHeader>
      <form id="admin-group-form" class="space-y-4" @submit.prevent="submit">
        <label :class="['block', fieldLabelClass]">
          {{ t("adminConsole.groups.form.name") }}
          <Input v-model="name" :placeholder="t('adminConsole.groups.form.namePlaceholder')" maxlength="120" data-testid="group-form-name" />
        </label>
        <label :class="['block', fieldLabelClass]">
          {{ t("adminConsole.groups.form.description") }}
          <textarea
            v-model="description"
            rows="3"
            maxlength="500"
            :placeholder="t('adminConsole.groups.form.descriptionPlaceholder')"
            class="w-full rounded-md border border-input bg-transparent px-2.5 py-1.5 text-sm font-normal text-foreground outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
            data-testid="group-form-description"
          />
        </label>
        <p v-if="error" class="text-sm text-destructive" data-testid="group-form-error">{{ error }}</p>
      </form>
      <DialogFooter>
        <Button variant="outline" @click="emit('update:open', false)">{{ t("common.cancel") }}</Button>
        <Button type="submit" form="admin-group-form" :disabled="!canSubmit" data-testid="group-form-submit">
          <Loader2 v-if="busy" class="animate-spin" />
          {{ editing ? t("adminConsole.groups.form.save") : t("adminConsole.groups.form.create") }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
