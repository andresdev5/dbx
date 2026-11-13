<script setup lang="ts">
import { computed, ref } from "vue";
import { useI18n } from "vue-i18n";
import { ArrowLeft, KeyRound, Pencil, ShieldAlert, ShieldOff, Trash2, UserRoundCheck, UserRoundX } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { accessAdmin, type UserGroup } from "@/lib/auth/accessAdmin";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { useAdminNavigator } from "@/lib/auth/adminNavigation";
import AuditSection from "../activity/AuditSection.vue";
import SessionsSection from "../activity/SessionsSection.vue";
import EffectiveSection from "../grants/EffectiveSection.vue";
import GrantsSection from "../grants/GrantsSection.vue";
import AdminAvatar from "../shared/AdminAvatar.vue";
import AdminBadge from "../shared/AdminBadge.vue";
import AdminTabs from "../shared/AdminTabs.vue";
import { useAdminText } from "../shared/adminUi";
import IssuedPasswordDialog from "./IssuedPasswordDialog.vue";
import UserFormDialog from "./UserFormDialog.vue";
import { useUserActions } from "./useUserActions";

const props = defineProps<{ userId: string; tab?: string }>();
const { t } = useI18n();
const { dateTime, relative, errorText } = useAdminText();
const directory = useAdminDirectory();
const navigator = useAdminNavigator();
const actions = useUserActions();

const activeTab = ref(props.tab ?? "overview");
const formOpen = ref(false);
const membershipBusy = ref("");
const membershipError = ref("");

const user = computed(() => directory.users.value.find((candidate) => candidate.id === props.userId) ?? null);
const isSelf = computed(() => props.userId === directory.currentUserId.value);
const memberGroups = computed(() => directory.groups.value.filter((group) => group.member_ids.includes(props.userId)));

const tabs = computed(() => [
  { key: "overview", label: t("adminConsole.users.detail.tabs.overview") },
  { key: "groups", label: t("adminConsole.users.detail.tabs.groups"), count: memberGroups.value.length },
  { key: "permissions", label: t("adminConsole.users.detail.tabs.permissions") },
  { key: "effective", label: t("adminConsole.users.detail.tabs.effective") },
  { key: "sessions", label: t("adminConsole.users.detail.tabs.sessions") },
  { key: "activity", label: t("adminConsole.users.detail.tabs.activity") },
]);

function back() {
  navigator.go({ section: "users" });
}

async function removeUser() {
  if (!user.value) return;
  if (await actions.remove(user.value)) back();
}

async function toggleMembership(group: UserGroup, member: boolean) {
  membershipBusy.value = group.id;
  membershipError.value = "";
  try {
    const members = member ? [...new Set([...group.member_ids, props.userId])] : group.member_ids.filter((id) => id !== props.userId);
    await accessAdmin.setGroupMembers(group.id, members);
    await directory.refreshGroups();
  } catch (e) {
    membershipError.value = errorText(e);
  } finally {
    membershipBusy.value = "";
  }
}
</script>

<template>
  <section class="space-y-5" data-testid="admin-user-detail">
    <button type="button" class="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground" data-testid="admin-user-back" @click="back">
      <ArrowLeft class="h-4 w-4" />
      {{ t("adminConsole.users.detail.backToUsers") }}
    </button>

    <div v-if="!user && directory.loaded.value" class="rounded-lg border border-dashed border-border px-4 py-10 text-center text-sm text-muted-foreground">{{ t("adminConsole.users.detail.notFound") }}</div>

    <template v-else-if="user">
      <div class="flex flex-wrap items-start gap-4">
        <AdminAvatar :name="user.display_name || user.username" size="lg" :muted="!user.active" />
        <div class="min-w-0 flex-1 space-y-1.5">
          <h2 class="flex flex-wrap items-center gap-2 text-xl font-semibold tracking-tight">
            {{ user.display_name || user.username }}
            <AdminBadge v-if="isSelf" tone="info">{{ t("adminConsole.you") }}</AdminBadge>
          </h2>
          <p class="text-sm text-muted-foreground">{{ user.username }}</p>
          <div class="flex flex-wrap items-center gap-1.5">
            <AdminBadge :tone="user.role === 'admin' ? 'primary' : 'neutral'">{{ user.role === "admin" ? t("auth.roleAdmin") : t("auth.roleUser") }}</AdminBadge>
            <AdminBadge :tone="user.active ? 'success' : 'neutral'" dot>{{ user.active ? t("adminConsole.users.status.active") : t("adminConsole.users.status.disabled") }}</AdminBadge>
            <AdminBadge :tone="user.mfa_enabled ? 'success' : user.mfa_required ? 'warning' : 'neutral'"> 2FA · {{ user.mfa_enabled ? t("adminConsole.users.mfa.enabled") : user.mfa_required ? t("adminConsole.users.mfa.pending") : t("adminConsole.users.mfa.off") }} </AdminBadge>
          </div>
        </div>
        <div class="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" data-testid="admin-user-edit" @click="formOpen = true">
            <Pencil />
            {{ t("adminConsole.users.actions.edit") }}
          </Button>
          <template v-if="!isSelf">
            <Button variant="outline" size="sm" :disabled="actions.busyId.value === user.id" data-testid="admin-user-toggle-active" @click="actions.toggleActive(user)">
              <UserRoundX v-if="user.active" />
              <UserRoundCheck v-else />
              {{ user.active ? t("adminConsole.users.actions.disable") : t("adminConsole.users.actions.enable") }}
            </Button>
            <Button variant="destructive" size="sm" :disabled="actions.busyId.value === user.id" data-testid="admin-user-delete" @click="removeUser">
              <Trash2 />
              {{ t("adminConsole.users.actions.delete") }}
            </Button>
          </template>
        </div>
      </div>

      <p v-if="actions.error.value" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">{{ actions.error.value }}</p>

      <AdminTabs v-model="activeTab" :tabs="tabs" />

      <div v-if="activeTab === 'overview'" class="grid gap-4 lg:grid-cols-2">
        <div class="rounded-lg border border-border/70 p-4">
          <h3 class="mb-3 text-sm font-semibold">{{ t("adminConsole.users.detail.profile") }}</h3>
          <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2.5 text-sm">
            <dt class="text-muted-foreground">{{ t("adminConsole.users.detail.username") }}</dt>
            <dd class="font-mono">{{ user.username }}</dd>
            <dt class="text-muted-foreground">{{ t("adminConsole.users.detail.displayName") }}</dt>
            <dd>{{ user.display_name || "—" }}</dd>
            <dt class="text-muted-foreground">{{ t("adminConsole.users.detail.role") }}</dt>
            <dd>{{ user.role === "admin" ? t("auth.roleAdmin") : t("auth.roleUser") }}</dd>
            <dt class="text-muted-foreground">{{ t("adminConsole.users.detail.created") }}</dt>
            <dd>{{ dateTime(user.created_at, "—") }}</dd>
            <dt class="text-muted-foreground">{{ t("adminConsole.users.detail.lastLogin") }}</dt>
            <dd :title="dateTime(user.last_login_at)">{{ relative(user.last_login_at, t("adminConsole.never")) }}</dd>
          </dl>
        </div>
        <div class="rounded-lg border border-border/70 p-4">
          <h3 class="mb-3 text-sm font-semibold">{{ t("adminConsole.users.detail.security") }}</h3>
          <div class="space-y-4 text-sm">
            <div class="flex items-start justify-between gap-3">
              <div>
                <p class="font-medium">{{ t("adminConsole.users.detail.password") }}</p>
                <p class="text-xs text-muted-foreground">{{ user.must_change_password ? t("adminConsole.users.detail.passwordPending") : t("adminConsole.users.detail.passwordOk") }}</p>
              </div>
              <Button v-if="!isSelf" variant="outline" size="sm" :disabled="actions.busyId.value === user.id" data-testid="admin-user-reset-password" @click="actions.resetPassword(user)">
                <KeyRound />
                {{ t("adminConsole.users.actions.resetPassword") }}
              </Button>
            </div>
            <div class="flex items-start justify-between gap-3">
              <div>
                <p class="font-medium">{{ t("adminConsole.users.detail.mfa") }}</p>
                <p class="text-xs text-muted-foreground">{{ user.mfa_enabled ? t("adminConsole.users.mfa.enabled") : t("adminConsole.users.mfa.off") }} · {{ user.mfa_required ? t("adminConsole.users.detail.mfaRequired") : t("adminConsole.users.detail.mfaOptional") }}</p>
              </div>
              <div v-if="!isSelf" class="flex items-center gap-2">
                <Button v-if="user.mfa_enabled" variant="outline" size="sm" :disabled="actions.busyId.value === user.id" data-testid="admin-user-reset-mfa" @click="actions.resetMfa(user)">
                  <ShieldOff />
                  {{ t("adminConsole.users.actions.resetMfa") }}
                </Button>
                <label class="flex items-center gap-2 text-xs text-muted-foreground">
                  <ShieldAlert class="h-3.5 w-3.5" />
                  {{ t("adminConsole.users.filters.mfaRequired") }}
                  <Switch :model-value="Boolean(user.mfa_required)" :disabled="actions.busyId.value === user.id" data-testid="admin-user-mfa-required" @update:model-value="actions.toggleMfaRequired(user)" />
                </label>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-else-if="activeTab === 'groups'" class="space-y-3">
        <p class="text-sm text-muted-foreground">{{ t("adminConsole.users.detail.groupsDescription") }}</p>
        <p v-if="membershipError" class="text-sm text-destructive">{{ membershipError }}</p>
        <div v-if="!directory.groups.value.length" class="rounded-lg border border-dashed border-border px-4 py-8 text-center text-sm text-muted-foreground">{{ t("adminConsole.users.detail.noGroups") }}</div>
        <div v-else class="divide-y divide-border/60 overflow-hidden rounded-lg border border-border/70">
          <div v-for="group in directory.groups.value" :key="group.id" class="flex items-center gap-3 px-4 py-2.5" data-testid="admin-user-group">
            <div class="min-w-0 flex-1">
              <button type="button" class="truncate text-sm font-medium hover:underline" @click="navigator.go({ section: 'group', id: group.id })">{{ group.name }}</button>
              <p v-if="group.description" class="truncate text-xs text-muted-foreground">{{ group.description }}</p>
            </div>
            <span class="text-xs text-muted-foreground">{{ group.member_ids.includes(user.id) ? t("adminConsole.users.detail.member") : t("adminConsole.users.detail.notMember") }}</span>
            <Switch :model-value="group.member_ids.includes(user.id)" :disabled="membershipBusy === group.id" @update:model-value="(value: boolean) => toggleMembership(group, value)" />
          </div>
        </div>
      </div>

      <div v-else-if="activeTab === 'permissions'" class="space-y-3">
        <p class="text-sm text-muted-foreground">{{ t("adminConsole.users.detail.permissionsDescription") }}</p>
        <p v-if="user.role === 'admin'" class="rounded-md bg-sky-500/10 px-3 py-2 text-xs text-sky-700 dark:text-sky-300">{{ t("adminConsole.users.detail.adminNote") }}</p>
        <GrantsSection :subject="{ kind: 'user', id: user.id }" embedded />
      </div>

      <EffectiveSection v-else-if="activeTab === 'effective'" :user-id="user.id" embedded />
      <SessionsSection v-else-if="activeTab === 'sessions'" :user-id="user.id" embedded />
      <AuditSection v-else-if="activeTab === 'activity'" :user-id="user.id" embedded />

      <UserFormDialog v-model:open="formOpen" :user="user" />
      <IssuedPasswordDialog :issued="actions.issued.value" @close="actions.issued.value = null" />
    </template>
  </section>
</template>
