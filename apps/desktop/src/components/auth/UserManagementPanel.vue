<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Copy, KeyRound, Loader2, ShieldAlert, ShieldOff, Trash2, UserPlus, UserRoundCheck, UserRoundX } from "@lucide/vue";
import { apiUrl } from "@/lib/common/webPath";
import { translateBackendError } from "@/i18n/backend-errors";
import { readAuthErrorCode } from "@/lib/startup/startupAuthentication";

interface ManagedUser {
  id: string;
  username: string;
  display_name: string | null;
  role: "admin" | "user";
  active: boolean;
  must_change_password: boolean;
  mfa_enabled: boolean;
  mfa_required: boolean;
  last_login_at: number | null;
  created_at: number;
}

const props = defineProps<{ currentUserId: string }>();
const { t, locale } = useI18n();

const users = ref<ManagedUser[]>([]);
const loading = ref(false);
const busyUserId = ref("");
const error = ref("");
const issued = ref<{ username: string; password: string } | null>(null);
const copied = ref(false);

const newUsername = ref("");
const newDisplayName = ref("");
const newRole = ref<"admin" | "user">("user");
const newPassword = ref("");
const creating = ref(false);
const mfaRequiredAll = ref(false);
const savingPolicy = ref(false);

async function call<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(apiUrl(`/api/admin/users/${path}`), {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const code = await readAuthErrorCode(response);
    throw new Error(translateBackendError(t, code) || t("users.actionFailed"));
  }
  return (await response.json()) as T;
}

async function refresh() {
  loading.value = true;
  error.value = "";
  try {
    const [loadedUsers, policy] = await Promise.all([call<ManagedUser[]>("list", {}), call<{ required_all: boolean }>("mfa-policy", {})]);
    users.value = loadedUsers;
    mfaRequiredAll.value = policy.required_all;
  } catch (e: any) {
    error.value = e?.message || t("users.actionFailed");
  } finally {
    loading.value = false;
  }
}

function replaceUser(updated: ManagedUser) {
  users.value = users.value.map((user) => (user.id === updated.id ? updated : user));
}

function showIssuedPassword(username: string, password?: string) {
  copied.value = false;
  issued.value = password ? { username, password } : null;
}

async function createUser() {
  creating.value = true;
  error.value = "";
  try {
    const result = await call<{ user: ManagedUser; temporary_password?: string }>("create", {
      username: newUsername.value.trim(),
      display_name: newDisplayName.value.trim() || null,
      role: newRole.value,
      password: newPassword.value || null,
    });
    users.value = [...users.value, result.user].sort((a, b) => a.username.localeCompare(b.username));
    showIssuedPassword(result.user.username, result.temporary_password);
    newUsername.value = "";
    newDisplayName.value = "";
    newRole.value = "user";
    newPassword.value = "";
  } catch (e: any) {
    error.value = e?.message || t("users.actionFailed");
  } finally {
    creating.value = false;
  }
}

async function runOnUser(user: ManagedUser, action: () => Promise<void>) {
  busyUserId.value = user.id;
  error.value = "";
  try {
    await action();
  } catch (e: any) {
    error.value = e?.message || t("users.actionFailed");
  } finally {
    busyUserId.value = "";
  }
}

function changeRole(user: ManagedUser, role: "admin" | "user") {
  if (role === user.role) return;
  void runOnUser(user, async () => replaceUser(await call<ManagedUser>("update", { id: user.id, display_name: user.display_name, role })));
}

function toggleActive(user: ManagedUser) {
  void runOnUser(user, async () => replaceUser(await call<ManagedUser>("set-active", { id: user.id, active: !user.active })));
}

function resetPassword(user: ManagedUser) {
  if (!window.confirm(t("users.confirmReset", { username: user.username }))) return;
  void runOnUser(user, async () => {
    const result = await call<{ user: ManagedUser; temporary_password?: string }>("reset-password", { id: user.id });
    replaceUser(result.user);
    showIssuedPassword(user.username, result.temporary_password);
  });
}

function toggleMfaRequired(user: ManagedUser) {
  void runOnUser(user, async () => replaceUser(await call<ManagedUser>("set-mfa-required", { id: user.id, required: !user.mfa_required })));
}

function resetMfa(user: ManagedUser) {
  if (!window.confirm(t("mfa.confirmReset", { username: user.username }))) return;
  void runOnUser(user, async () => replaceUser(await call<ManagedUser>("reset-mfa", { id: user.id })));
}

async function changeMfaPolicy(requiredAll: boolean) {
  if (!window.confirm(requiredAll ? t("mfa.confirmRequireAll") : t("mfa.confirmUnrequireAll"))) {
    mfaRequiredAll.value = !requiredAll;
    return;
  }
  savingPolicy.value = true;
  error.value = "";
  try {
    mfaRequiredAll.value = (await call<{ required_all: boolean }>("mfa-policy/save", { required_all: requiredAll })).required_all;
    users.value = await call<ManagedUser[]>("list", {});
  } catch (e: any) {
    mfaRequiredAll.value = !requiredAll;
    error.value = e?.message || t("users.actionFailed");
  } finally {
    savingPolicy.value = false;
  }
}

function deleteUser(user: ManagedUser) {
  if (!window.confirm(t("users.confirmDelete", { username: user.username }))) return;
  void runOnUser(user, async () => {
    await call("delete", { id: user.id });
    users.value = users.value.filter((candidate) => candidate.id !== user.id);
  });
}

async function copyIssuedPassword() {
  if (!issued.value) return;
  try {
    await navigator.clipboard.writeText(issued.value.password);
    copied.value = true;
  } catch {
    copied.value = false;
  }
}

function lastLogin(user: ManagedUser): string {
  return user.last_login_at ? new Date(user.last_login_at).toLocaleString(String(locale.value)) : t("users.never");
}

onMounted(() => {
  void refresh();
});
</script>

<template>
  <div class="space-y-4" data-testid="user-management">
    <div class="space-y-1">
      <Label class="text-base">{{ t("users.title") }}</Label>
      <p class="text-sm text-muted-foreground">{{ t("users.description") }}</p>
    </div>

    <div v-if="issued" class="space-y-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2" data-testid="issued-password">
      <p class="text-sm">{{ t("users.temporaryPassword", { username: issued.username }) }}</p>
      <div class="flex items-center gap-2">
        <code class="flex-1 truncate rounded bg-background px-2 py-1 font-mono text-sm">{{ issued.password }}</code>
        <Button variant="outline" size="sm" class="gap-1" @click="copyIssuedPassword">
          <Copy class="h-3.5 w-3.5" />
          {{ copied ? t("users.copied") : t("users.copy") }}
        </Button>
      </div>
    </div>

    <p v-if="error" class="text-sm text-destructive" data-testid="user-management-error">{{ error }}</p>

    <label class="flex items-center gap-2 text-sm">
      <input v-model="mfaRequiredAll" type="checkbox" :disabled="savingPolicy || loading" data-testid="mfa-required-all" @change="changeMfaPolicy(mfaRequiredAll)" />
      {{ t("mfa.requireAll") }}
    </label>

    <div class="overflow-hidden rounded-md border border-border/60">
      <div v-if="loading" class="flex items-center gap-2 px-3 py-4 text-sm text-muted-foreground">
        <Loader2 class="h-4 w-4 animate-spin" />
        {{ t("auth.processing") }}
      </div>
      <div v-for="user in users" v-else :key="user.id" class="flex flex-wrap items-center gap-3 border-b border-border/60 px-3 py-2 last:border-b-0" data-testid="managed-user">
        <div class="min-w-0 flex-1">
          <p class="truncate text-sm font-medium">
            {{ user.display_name || user.username }}
            <span v-if="user.id === props.currentUserId" class="text-xs font-normal text-muted-foreground">{{ t("users.you") }}</span>
            <span :class="['ml-1 rounded px-1.5 py-0.5 text-xs font-medium', user.mfa_enabled ? 'bg-green-500/15 text-green-600' : 'bg-amber-500/15 text-amber-600']" data-testid="mfa-badge">
              {{ user.mfa_enabled ? t("mfa.badgeOn") : t("mfa.badgeOff") }}
            </span>
          </p>
          <p class="truncate text-xs text-muted-foreground">
            {{ user.username }} · {{ user.active ? t("users.active") : t("users.disabled") }}<template v-if="user.must_change_password"> · {{ t("users.mustChange") }}</template
            ><template v-if="user.mfa_required"> · {{ t("mfa.requiredShort") }}</template> · {{ t("users.lastLogin") }}: {{ lastLogin(user) }}
          </p>
        </div>
        <select
          class="h-8 rounded-md border border-input bg-background px-2 text-sm disabled:opacity-60"
          :value="user.role"
          :disabled="user.id === props.currentUserId || busyUserId === user.id"
          :aria-label="t('users.role')"
          @change="changeRole(user, ($event.target as HTMLSelectElement).value as 'admin' | 'user')"
        >
          <option value="user">{{ t("auth.roleUser") }}</option>
          <option value="admin">{{ t("auth.roleAdmin") }}</option>
        </select>
        <template v-if="user.id !== props.currentUserId">
          <Button variant="ghost" size="icon" class="h-8 w-8" :title="user.active ? t('users.disable') : t('users.enable')" :disabled="busyUserId === user.id" @click="toggleActive(user)">
            <UserRoundX v-if="user.active" class="h-4 w-4" />
            <UserRoundCheck v-else class="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" class="h-8 w-8" :title="t('users.resetPassword')" :disabled="busyUserId === user.id" @click="resetPassword(user)">
            <KeyRound class="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" :class="['h-8 w-8', user.mfa_required ? 'text-amber-600' : '']" :title="user.mfa_required ? t('mfa.unrequireUser') : t('mfa.requireUser')" :disabled="busyUserId === user.id" data-testid="mfa-toggle-required" @click="toggleMfaRequired(user)">
            <ShieldAlert class="h-4 w-4" />
          </Button>
          <Button v-if="user.mfa_enabled" variant="ghost" size="icon" class="h-8 w-8" :title="t('mfa.reset')" :disabled="busyUserId === user.id" data-testid="mfa-reset" @click="resetMfa(user)">
            <ShieldOff class="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" class="h-8 w-8 text-destructive hover:text-destructive" :title="t('users.delete')" :disabled="busyUserId === user.id" @click="deleteUser(user)">
            <Trash2 class="h-4 w-4" />
          </Button>
        </template>
      </div>
    </div>

    <form class="space-y-2 rounded-md border border-border/60 p-3" data-testid="create-user-form" @submit.prevent="createUser">
      <p class="text-sm font-medium">{{ t("users.createTitle") }}</p>
      <div class="grid gap-2 sm:grid-cols-2">
        <Input v-model="newUsername" :placeholder="t('auth.username')" class="h-9" autocomplete="off" spellcheck="false" data-testid="new-user-username" />
        <Input v-model="newDisplayName" :placeholder="t('users.displayName')" class="h-9" autocomplete="off" />
        <Input v-model="newPassword" type="password" :placeholder="t('users.passwordOptional')" class="h-9" autocomplete="new-password" />
        <select v-model="newRole" class="h-9 rounded-md border border-input bg-background px-2 text-sm" :aria-label="t('users.role')">
          <option value="user">{{ t("auth.roleUser") }}</option>
          <option value="admin">{{ t("auth.roleAdmin") }}</option>
        </select>
      </div>
      <div class="flex justify-end">
        <Button type="submit" size="sm" class="gap-1" :disabled="creating || !newUsername.trim()">
          <Loader2 v-if="creating" class="h-3.5 w-3.5 animate-spin" />
          <UserPlus v-else class="h-3.5 w-3.5" />
          {{ t("users.create") }}
        </Button>
      </div>
    </form>
  </div>
</template>
