<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Label } from "@/components/ui/label";
import { Loader2 } from "@lucide/vue";
import { translateBackendError } from "@/i18n/backend-errors";
import { accessAdmin, listConnections, type ConnectionSummary, type DataRole, type ManagedUser, type UserGroup } from "@/lib/auth/accessAdmin";
import AccessGroups from "./AccessGroups.vue";
import AccessRoles from "./AccessRoles.vue";
import AccessGrants from "./AccessGrants.vue";
import AccessEffective from "./AccessEffective.vue";
import AccessFunctions from "./AccessFunctions.vue";

type Section = "grants" | "groups" | "roles" | "effective" | "functions";

const { t } = useI18n();
const section = ref<Section>("grants");
const sections: Section[] = ["grants", "groups", "roles", "effective", "functions"];
const users = ref<ManagedUser[]>([]);
const groups = ref<UserGroup[]>([]);
const roles = ref<DataRole[]>([]);
const connections = ref<ConnectionSummary[]>([]);
const loaded = ref(false);
const error = ref("");

function errorText(e: unknown): string {
  const code = e instanceof Error ? e.message : String(e);
  return translateBackendError(t, code) || t("users.actionFailed");
}

async function refresh() {
  error.value = "";
  try {
    const [loadedUsers, loadedGroups, loadedRoles, loadedConnections] = await Promise.all([accessAdmin.users(), accessAdmin.groups(), accessAdmin.roles(), listConnections()]);
    users.value = loadedUsers;
    groups.value = loadedGroups;
    roles.value = loadedRoles;
    connections.value = loadedConnections;
  } catch (e) {
    error.value = errorText(e);
  } finally {
    loaded.value = true;
  }
}

onMounted(() => {
  void refresh();
});
</script>

<template>
  <div class="space-y-4" data-testid="access-control">
    <div class="space-y-1">
      <Label class="text-base">{{ t("access.title") }}</Label>
      <p class="text-sm text-muted-foreground">{{ t("access.description") }}</p>
    </div>
    <div class="flex flex-wrap gap-1" role="tablist">
      <button
        v-for="item in sections"
        :key="item"
        type="button"
        role="tab"
        :aria-selected="section === item"
        :class="['rounded-md px-3 py-1.5 text-sm transition-colors', section === item ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted hover:text-foreground']"
        :data-testid="`access-tab-${item}`"
        @click="section = item"
      >
        {{ t(`access.sections.${item}`) }}
      </button>
    </div>
    <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
    <div v-if="!loaded" class="flex items-center gap-2 text-sm text-muted-foreground">
      <Loader2 class="h-4 w-4 animate-spin" />
      {{ t("auth.processing") }}
    </div>
    <template v-else>
      <AccessGrants v-if="section === 'grants'" :users="users" :groups="groups" :roles="roles" :connections="connections" />
      <AccessGroups v-else-if="section === 'groups'" :users="users" :groups="groups" @changed="refresh" />
      <AccessRoles v-else-if="section === 'roles'" :roles="roles" @changed="refresh" />
      <AccessEffective v-else-if="section === 'effective'" :users="users" :groups="groups" :connections="connections" />
      <AccessFunctions v-else :connections="connections" />
    </template>
  </div>
</template>
