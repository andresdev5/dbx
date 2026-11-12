import { apiUrl } from "@/lib/common/webPath";
import { readAuthErrorCode } from "@/lib/startup/startupAuthentication";

export const OPERATIONS = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "CREATE", "ALTER", "DROP", "GRANT", "EXECUTE", "EXPORT", "IMPORT", "UNCLASSIFIED"] as const;
export type Operation = (typeof OPERATIONS)[number];

export interface ManagedUser {
  id: string;
  username: string;
  display_name: string | null;
  role: "admin" | "user";
  active: boolean;
}

export interface UserGroup {
  id: string;
  name: string;
  description: string | null;
  member_ids: string[];
}

export interface DataRole {
  id: string;
  name: string;
  operations: Operation[];
  builtin: boolean;
  description: string | null;
}

export type GrantSubject = { kind: "user"; id: string } | { kind: "group"; id: string } | { kind: "system" };

export interface GrantResource {
  connectionId: string;
  database?: string;
  schema?: string;
  table?: string;
}

export type GrantScope = { kind: "all" } | { kind: "connection_group"; value: string } | { kind: "resource"; value: GrantResource };

export interface Grant {
  id: string;
  subject: GrantSubject;
  scope: GrantScope;
  effect: "allow" | "deny";
  operations: Operation[] | null;
  role_id: string | null;
  expires_at: number | null;
  note: string | null;
}

export interface GrantDraft {
  id?: string;
  subject: GrantSubject;
  scope: GrantScope;
  effect: "allow" | "deny";
  operations?: Operation[] | null;
  role_id?: string | null;
  expires_at?: number | null;
  note?: string | null;
}

export interface EffectiveRule {
  grant_id: string;
  via_group: string | null;
  resource: GrantResource;
  effect: "allow" | "deny";
  operations: Operation[];
}

export interface EffectivePermissions {
  visible: boolean;
  implicit_admin: boolean;
  connection_operations: Operation[];
  rules: EffectiveRule[];
}

export interface ConnectionPolicy {
  connection_id: string;
  strict_function_mode: boolean;
  function_allowlist: string[];
}

export interface ConnectionSummary {
  id: string;
  name: string;
}

export class AccessAdminError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

async function call<T>(path: string, body: unknown = {}): Promise<T> {
  const response = await fetch(apiUrl(`/api/admin/${path}`), {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new AccessAdminError(await readAuthErrorCode(response));
  return (await response.json()) as T;
}

export const accessAdmin = {
  users: () => call<ManagedUser[]>("users/list"),
  groups: () => call<UserGroup[]>("groups/list"),
  createGroup: (name: string, description: string | null) => call<UserGroup>("groups/create", { name, description }),
  updateGroup: (id: string, name: string, description: string | null) => call("groups/update", { id, name, description }),
  setGroupMembers: (id: string, userIds: string[]) => call("groups/set-members", { id, user_ids: userIds }),
  deleteGroup: (id: string) => call("groups/delete", { id }),
  roles: () => call<DataRole[]>("roles/list"),
  createRole: (name: string, operations: Operation[], description: string | null) => call<DataRole>("roles/create", { name, operations, description }),
  updateRole: (id: string, name: string, operations: Operation[], description: string | null) => call("roles/update", { id, name, operations, description }),
  deleteRole: (id: string) => call("roles/delete", { id }),
  grants: (subject?: GrantSubject) => call<Grant[]>("grants/list", subject ? { subject } : {}),
  saveGrant: (draft: GrantDraft) => call<Grant>("grants/save", draft),
  deleteGrant: (id: string) => call("grants/delete", { id }),
  effective: (userId: string, connectionId: string) => call<EffectivePermissions>("grants/effective", { user_id: userId, connection_id: connectionId }),
  policies: () => call<ConnectionPolicy[]>("connection-policies/list"),
  savePolicy: (policy: ConnectionPolicy) => call<ConnectionPolicy>("connection-policies/save", policy),
};

export async function listConnections(): Promise<ConnectionSummary[]> {
  const response = await fetch(apiUrl("/api/connection/list"), { credentials: "same-origin" });
  if (!response.ok) throw new AccessAdminError(await readAuthErrorCode(response));
  const rows = (await response.json()) as { id: string; name: string }[];
  return rows.map((row) => ({ id: row.id, name: row.name })).sort((a, b) => a.name.localeCompare(b.name));
}

export function describeResource(resource: GrantResource, connections: ConnectionSummary[]): string {
  const connection = connections.find((candidate) => candidate.id === resource.connectionId)?.name ?? resource.connectionId;
  return [connection, resource.database, resource.schema, resource.table].filter(Boolean).join(" / ");
}

export function endOfDay(date: string): number | null {
  if (!date) return null;
  const parsed = new Date(`${date}T23:59:59`);
  return Number.isNaN(parsed.getTime()) ? null : parsed.getTime();
}
