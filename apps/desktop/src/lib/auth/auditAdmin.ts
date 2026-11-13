import { apiUrl } from "@/lib/common/webPath";
import { readAuthErrorCode } from "@/lib/startup/startupAuthentication";
import { AccessAdminError, type Operation } from "@/lib/auth/accessAdmin";

export const AUDIT_EVENTS = [
  "sql",
  "data_access",
  "connection_denied",
  "login_succeeded",
  "login_failed",
  "logout",
  "setup_completed",
  "setup_failed",
  "password_changed",
  "password_change_failed",
  "user_created",
  "user_updated",
  "user_activated",
  "user_deactivated",
  "user_password_reset",
  "user_deleted",
  "group_created",
  "group_updated",
  "group_members_set",
  "group_deleted",
  "role_created",
  "role_updated",
  "role_deleted",
  "grant_saved",
  "grant_deleted",
  "connection_policy_saved",
  "backup_schedule_saved",
  "backup_schedule_deleted",
  "backup_owner_changed",
  "session_revoked",
  "user_sessions_revoked",
  "audit_revealed",
  "audit_exported",
  "audit_events_dropped",
  "secret_key_rotated",
] as const;

export interface AuditEntry {
  id: number;
  event_id: string;
  ts: number;
  user_id: string | null;
  username: string | null;
  acting_principal: "user" | "system" | "local" | "anonymous";
  task_id: string | null;
  session_ref: string | null;
  ip: string | null;
  event: string;
  connection_id: string | null;
  database_name: string | null;
  schema_name: string | null;
  table_names: string | null;
  operations: Operation[];
  decision: "allow" | "deny" | null;
  reason: string | null;
  has_statement: boolean;
  rows_affected: number | null;
  duration_ms: number | null;
  detail: Record<string, unknown> | null;
}

export interface AuditPage {
  entries: AuditEntry[];
  next_before_id: number | null;
  dropped_events: number;
}

export interface AuditQuery {
  user_id?: string;
  connection_id?: string;
  decision?: "allow" | "deny";
  event?: string;
  from?: number;
  to?: number;
  statement?: string;
  before_id?: number;
  limit?: number;
  include_statements?: boolean;
}

export interface LiveSession {
  id: string;
  session_ref: string;
  user_id: string;
  username: string | null;
  created_at: number;
  last_seen_at: number;
  expires_at: number | null;
  ip: string | null;
  user_agent: string | null;
  current: boolean;
}

async function post(path: string, body: unknown): Promise<Response> {
  const response = await fetch(apiUrl(`/api/admin/${path}`), {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new AccessAdminError(await readAuthErrorCode(response));
  return response;
}

export function cleanQuery(query: AuditQuery): AuditQuery {
  const cleaned: AuditQuery = {};
  for (const [key, value] of Object.entries(query) as [keyof AuditQuery, unknown][]) {
    if (value === undefined || value === null || value === "") continue;
    (cleaned as Record<string, unknown>)[key] = typeof value === "string" ? value.trim() || undefined : value;
  }
  return cleaned;
}

export function startOfDay(date: string): number | undefined {
  if (!date) return undefined;
  const parsed = new Date(`${date}T00:00:00`);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.getTime();
}

export function endOfDayMillis(date: string): number | undefined {
  if (!date) return undefined;
  const parsed = new Date(`${date}T23:59:59.999`);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.getTime();
}

function filenameFrom(response: Response): string {
  const disposition = response.headers.get("content-disposition") ?? "";
  return /filename="([^"]+)"/.exec(disposition)?.[1] ?? "dbx-audit.csv";
}

export const auditAdmin = {
  list: async (query: AuditQuery) => (await (await post("audit/list", cleanQuery(query))).json()) as AuditPage,
  reveal: async (eventId: string) => ((await (await post("audit/reveal", { event_id: eventId })).json()) as { statement: string }).statement,
  export: async (query: AuditQuery) => {
    const response = await post("audit/export", cleanQuery(query));
    return { filename: filenameFrom(response), content: await response.text(), truncated: response.headers.get("x-dbx-export-truncated") === "true" };
  },
  sessions: async (userId?: string) => (await (await post("sessions/list", userId ? { user_id: userId } : {})).json()) as LiveSession[],
  revokeSession: async (id: string) => ((await (await post("sessions/revoke", { id })).json()) as { revoked: number }).revoked,
  revokeUserSessions: async (userId: string) => ((await (await post("sessions/revoke", { user_id: userId })).json()) as { revoked: number }).revoked,
};

export function downloadText(filename: string, content: string, type = "text/csv") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
