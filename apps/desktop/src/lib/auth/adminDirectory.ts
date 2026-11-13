import { inject, ref, type InjectionKey, type Ref } from "vue";
import { accessAdmin, listConnections, type ConnectionSummary, type DataRole, type ManagedUser, type UserGroup } from "@/lib/auth/accessAdmin";

export interface AdminDirectory {
  users: Ref<ManagedUser[]>;
  groups: Ref<UserGroup[]>;
  roles: Ref<DataRole[]>;
  connections: Ref<ConnectionSummary[]>;
  currentUserId: Ref<string>;
  loaded: Ref<boolean>;
  error: Ref<string>;
  refresh: () => Promise<void>;
  refreshUsers: () => Promise<void>;
  refreshGroups: () => Promise<void>;
  refreshRoles: () => Promise<void>;
  replaceUser: (user: ManagedUser) => void;
  userLabel: (id: string) => string;
  groupLabel: (id: string) => string;
  connectionLabel: (id: string) => string;
}

export const ADMIN_DIRECTORY: InjectionKey<AdminDirectory> = Symbol("dbx:admin-directory");

export function createAdminDirectory(currentUserId: Ref<string>): AdminDirectory {
  const users = ref<ManagedUser[]>([]);
  const groups = ref<UserGroup[]>([]);
  const roles = ref<DataRole[]>([]);
  const connections = ref<ConnectionSummary[]>([]);
  const loaded = ref(false);
  const error = ref("");

  async function guarded(action: () => Promise<void>) {
    error.value = "";
    try {
      await action();
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
    }
  }

  const refreshUsers = () =>
    guarded(async () => {
      users.value = await accessAdmin.users();
    });
  const refreshGroups = () =>
    guarded(async () => {
      groups.value = await accessAdmin.groups();
    });
  const refreshRoles = () =>
    guarded(async () => {
      roles.value = await accessAdmin.roles();
    });

  async function refresh() {
    await guarded(async () => {
      const [loadedUsers, loadedGroups, loadedRoles, loadedConnections] = await Promise.all([accessAdmin.users(), accessAdmin.groups(), accessAdmin.roles(), listConnections()]);
      users.value = loadedUsers;
      groups.value = loadedGroups;
      roles.value = loadedRoles;
      connections.value = loadedConnections;
    });
    loaded.value = true;
  }

  function replaceUser(user: ManagedUser) {
    users.value = users.value.some((candidate) => candidate.id === user.id) ? users.value.map((candidate) => (candidate.id === user.id ? user : candidate)) : [...users.value, user];
  }

  return {
    users,
    groups,
    roles,
    connections,
    currentUserId,
    loaded,
    error,
    refresh,
    refreshUsers,
    refreshGroups,
    refreshRoles,
    replaceUser,
    userLabel: (id) => users.value.find((user) => user.id === id)?.username ?? id,
    groupLabel: (id) => groups.value.find((group) => group.id === id)?.name ?? id,
    connectionLabel: (id) => connections.value.find((connection) => connection.id === id)?.name ?? id,
  };
}

export function useAdminDirectory(): AdminDirectory {
  const directory = inject(ADMIN_DIRECTORY, null);
  if (!directory) throw new Error("Admin directory is not provided");
  return directory;
}
