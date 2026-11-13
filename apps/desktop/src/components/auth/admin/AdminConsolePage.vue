<script setup lang="ts">
import { computed, onMounted, provide, ref, toRef, type Component } from "vue";
import { useI18n } from "vue-i18n";
import { BadgeCheck, Fingerprint, KeyRound, MonitorSmartphone, ScanEye, ScrollText, ShieldAlert, ShieldCheck, SquareFunction, Users, UsersRound } from "@lucide/vue";
import { ADMIN_CONFIRM, type AdminConfirmRequest } from "@/lib/auth/adminConfirm";
import { ADMIN_DIRECTORY, createAdminDirectory } from "@/lib/auth/adminDirectory";
import { ADMIN_NAV, ADMIN_NAVIGATOR, routeSection, type AdminRoute, type AdminSection } from "@/lib/auth/adminNavigation";
import AdminConfirmDialog from "./shared/AdminConfirmDialog.vue";
import UsersSection from "./users/UsersSection.vue";
import UserDetailPage from "./users/UserDetailPage.vue";
import GroupsSection from "./groups/GroupsSection.vue";
import GroupDetailPage from "./groups/GroupDetailPage.vue";
import RolesSection from "./roles/RolesSection.vue";
import GrantsSection from "./grants/GrantsSection.vue";
import EffectiveSection from "./grants/EffectiveSection.vue";
import FunctionsSection from "./grants/FunctionsSection.vue";
import SessionsSection from "./activity/SessionsSection.vue";
import AuditSection from "./activity/AuditSection.vue";
import IdentityProvidersSection from "./authentication/IdentityProvidersSection.vue";
import PoliciesSection from "./authentication/PoliciesSection.vue";

const props = defineProps<{ currentUserId: string }>();
const { t } = useI18n();

const ICONS: Record<AdminSection, Component> = {
  users: UsersRound,
  groups: Users,
  roles: BadgeCheck,
  grants: KeyRound,
  effective: ScanEye,
  functions: SquareFunction,
  sessions: MonitorSmartphone,
  audit: ScrollText,
  identity: Fingerprint,
  policies: ShieldAlert,
};

const directory = createAdminDirectory(toRef(props, "currentUserId"));
const route = ref<AdminRoute>({ section: "users" });
const activeSection = computed(() => routeSection(route.value));
const confirmDialog = ref<InstanceType<typeof AdminConfirmDialog> | null>(null);
const scroller = ref<HTMLElement | null>(null);

function go(next: AdminRoute) {
  route.value = next;
  scroller.value?.scrollTo({ top: 0 });
}

provide(ADMIN_DIRECTORY, directory);
provide(ADMIN_NAVIGATOR, { go });
provide(ADMIN_CONFIRM, (request: AdminConfirmRequest) => confirmDialog.value?.ask(request) ?? Promise.resolve(false));

onMounted(() => {
  void directory.refresh();
});
</script>

<template>
  <div class="flex h-full min-h-0 w-full bg-background" data-testid="admin-console">
    <aside class="hidden w-60 shrink-0 flex-col border-r border-border/70 bg-muted/20 md:flex">
      <div class="flex items-center gap-2.5 px-4 pb-3 pt-4">
        <span class="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/12 text-emerald-600 dark:text-emerald-400">
          <ShieldCheck class="h-4.5 w-4.5" />
        </span>
        <div class="min-w-0">
          <p class="truncate text-sm font-semibold">{{ t("adminConsole.title") }}</p>
          <p class="truncate text-[11px] text-muted-foreground">DBX Web</p>
        </div>
      </div>
      <nav class="min-h-0 flex-1 space-y-4 overflow-y-auto px-2 pb-4" :aria-label="t('adminConsole.title')">
        <div v-for="group in ADMIN_NAV" :key="group.key" class="space-y-0.5">
          <p class="px-2 pb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground/80">{{ t(`adminConsole.navGroups.${group.key}`) }}</p>
          <button
            v-for="section in group.sections"
            :key="section"
            type="button"
            :class="[
              'flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50',
              activeSection === section ? 'bg-background font-medium text-foreground shadow-sm ring-1 ring-border/70' : 'text-muted-foreground hover:bg-muted hover:text-foreground',
            ]"
            :aria-current="activeSection === section ? 'page' : undefined"
            :data-testid="`admin-nav-${section}`"
            @click="go({ section })"
          >
            <component :is="ICONS[section]" class="h-4 w-4 shrink-0" />
            <span class="truncate">{{ t(`adminConsole.sections.${section}`) }}</span>
          </button>
        </div>
      </nav>
    </aside>

    <div class="flex min-h-0 min-w-0 flex-1 flex-col">
      <div class="border-b border-border/70 px-4 py-2 md:hidden">
        <select class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm" :value="activeSection" :aria-label="t('adminConsole.title')" @change="go({ section: ($event.target as HTMLSelectElement).value as AdminSection })">
          <optgroup v-for="group in ADMIN_NAV" :key="group.key" :label="t(`adminConsole.navGroups.${group.key}`)">
            <option v-for="section in group.sections" :key="section" :value="section">{{ t(`adminConsole.sections.${section}`) }}</option>
          </optgroup>
        </select>
      </div>
      <main ref="scroller" class="min-h-0 flex-1 overflow-y-auto">
        <div class="mx-auto w-full max-w-6xl px-4 py-5 md:px-8 md:py-7">
          <p v-if="directory.error.value" class="mb-4 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive" data-testid="admin-directory-error">{{ directory.error.value }}</p>
          <UserDetailPage v-if="route.section === 'user'" :key="`user-${route.id}`" :user-id="route.id" :tab="route.tab" />
          <GroupDetailPage v-else-if="route.section === 'group'" :key="`group-${route.id}`" :group-id="route.id" :tab="route.tab" />
          <UsersSection v-else-if="route.section === 'users'" />
          <GroupsSection v-else-if="route.section === 'groups'" />
          <RolesSection v-else-if="route.section === 'roles'" />
          <GrantsSection v-else-if="route.section === 'grants'" />
          <EffectiveSection v-else-if="route.section === 'effective'" :user-id="route.userId" />
          <FunctionsSection v-else-if="route.section === 'functions'" />
          <SessionsSection v-else-if="route.section === 'sessions'" :user-id="route.userId" />
          <AuditSection v-else-if="route.section === 'audit'" :user-id="route.userId" />
          <IdentityProvidersSection v-else-if="route.section === 'identity'" />
          <PoliciesSection v-else-if="route.section === 'policies'" />
        </div>
      </main>
    </div>
    <AdminConfirmDialog ref="confirmDialog" />
  </div>
</template>
