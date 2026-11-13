<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Loader2 } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import PasswordInput from "@/components/ui/PasswordInput.vue";
import { userAdmin, type IssuedUser, type ManagedUser } from "@/lib/auth/accessAdmin";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { fieldLabelClass, selectClass, useAdminText } from "../shared/adminUi";

const props = defineProps<{ open: boolean; user?: ManagedUser | null }>();
const emit = defineEmits<{ "update:open": [open: boolean]; created: [result: IssuedUser]; updated: [user: ManagedUser] }>();
const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();

const username = ref("");
const displayName = ref("");
const role = ref<"admin" | "user">("user");
const password = ref("");
const busy = ref(false);
const error = ref("");

const editing = computed(() => Boolean(props.user));
const isSelf = computed(() => props.user?.id === directory.currentUserId.value);
const canSubmit = computed(() => !busy.value && (editing.value || username.value.trim().length > 0));

watch(
  () => props.open,
  (open) => {
    if (!open) return;
    username.value = props.user?.username ?? "";
    displayName.value = props.user?.display_name ?? "";
    role.value = props.user?.role ?? "user";
    password.value = "";
    error.value = "";
  },
  { immediate: true },
);

async function submit() {
  if (!canSubmit.value) return;
  busy.value = true;
  error.value = "";
  try {
    if (props.user) {
      const updated = await userAdmin.update(props.user.id, displayName.value.trim() || null, role.value);
      directory.replaceUser(updated);
      emit("updated", updated);
    } else {
      const result = await userAdmin.create({ username: username.value.trim(), display_name: displayName.value.trim() || null, role: role.value, password: password.value || null });
      directory.replaceUser(result.user);
      emit("created", result);
    }
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
    <DialogContent class="sm:max-w-lg" data-testid="user-form-dialog">
      <DialogHeader>
        <DialogTitle>{{ editing ? t("adminConsole.users.editUser") : t("adminConsole.users.newUser") }}</DialogTitle>
      </DialogHeader>
      <form id="admin-user-form" class="space-y-4" @submit.prevent="submit">
        <label :class="['block', fieldLabelClass]">
          {{ t("adminConsole.users.form.username") }}
          <Input v-model="username" :disabled="editing" autocomplete="off" spellcheck="false" data-testid="user-form-username" />
          <span v-if="!editing" class="block font-normal">{{ t("adminConsole.users.form.usernameHint") }}</span>
        </label>
        <label :class="['block', fieldLabelClass]">
          {{ t("adminConsole.users.form.displayName") }}
          <Input v-model="displayName" :placeholder="t('adminConsole.users.form.displayNamePlaceholder')" maxlength="120" data-testid="user-form-display-name" />
        </label>
        <label :class="['block', fieldLabelClass]">
          {{ t("adminConsole.users.form.role") }}
          <select v-model="role" :class="selectClass" :disabled="isSelf" data-testid="user-form-role">
            <option value="user">{{ t("auth.roleUser") }}</option>
            <option value="admin">{{ t("auth.roleAdmin") }}</option>
          </select>
          <span class="block font-normal">{{ t("adminConsole.users.form.roleHint") }}</span>
        </label>
        <label v-if="!editing" :class="['block', fieldLabelClass]">
          {{ t("adminConsole.users.form.password") }}
          <PasswordInput v-model="password" input-class="h-8" autocomplete="new-password" data-testid="user-form-password" />
          <span class="block font-normal">{{ t("adminConsole.users.form.passwordHint") }}</span>
        </label>
        <p v-if="error" class="text-sm text-destructive" data-testid="user-form-error">{{ error }}</p>
      </form>
      <DialogFooter>
        <Button variant="outline" @click="emit('update:open', false)">{{ t("common.cancel") }}</Button>
        <Button type="submit" form="admin-user-form" :disabled="!canSubmit" data-testid="user-form-submit">
          <Loader2 v-if="busy" class="animate-spin" />
          {{ editing ? t("adminConsole.users.form.save") : t("adminConsole.users.form.create") }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
