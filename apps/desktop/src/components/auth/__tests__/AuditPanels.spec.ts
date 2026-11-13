// @vitest-environment happy-dom

import { createApp, nextTick, ref, type App, type Component } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({
    t: (key: string, values?: Record<string, unknown>) => (values ? `${key}:${JSON.stringify(values)}` : key),
    te: (key: string) => key.startsWith("audit.events."),
    locale: ref("en"),
  }),
}));

import AuditLogPanel from "../audit/AuditLogPanel.vue";
import SessionsPanel from "../audit/SessionsPanel.vue";
import { cleanQuery, endOfDayMillis, startOfDay } from "@/lib/auth/auditAdmin";

const SQL_EVENT = {
  id: 7,
  event_id: "e-7",
  ts: 1_700_000_000_000,
  user_id: "u-ana",
  username: "ana",
  acting_principal: "user",
  task_id: null,
  session_ref: "abcdef0123456789",
  ip: "10.0.0.7",
  event: "sql",
  connection_id: "c-sales",
  database_name: "crm",
  schema_name: null,
  table_names: "orders",
  operations: ["DELETE"],
  decision: "deny",
  reason: "Permission denied: DELETE required on crm.orders",
  has_statement: true,
  rows_affected: null,
  duration_ms: null,
  detail: null,
};
const SYSTEM_EVENT = { ...SQL_EVENT, id: 6, event_id: "e-6", acting_principal: "system", task_id: "backup:run-1", username: null, user_id: null, decision: "allow", has_statement: false, operations: ["SELECT", "EXPORT"], event: "data_access" };
const SESSIONS = [
  { id: "h-admin", session_ref: "h-admin", user_id: "u-admin", username: "admin", created_at: 1, last_seen_at: 2, expires_at: null, ip: "127.0.0.1", user_agent: "Firefox", current: true },
  { id: "h-ana-1", session_ref: "h-ana-1", user_id: "u-ana", username: "ana", created_at: 1, last_seen_at: 2, expires_at: 3, ip: "10.0.0.7", user_agent: null, current: false },
  { id: "h-ana-2", session_ref: "h-ana-2", user_id: "u-ana", username: "ana", created_at: 1, last_seen_at: 2, expires_at: 3, ip: "10.0.0.8", user_agent: "Chrome", current: false },
];

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

async function flush() {
  for (let i = 0; i < 16; i += 1) {
    await Promise.resolve();
    await nextTick();
  }
}

function mount(component: Component): { root: HTMLElement; app: App } {
  const root = document.createElement("div");
  document.body.append(root);
  const app = createApp(component);
  app.mount(root);
  return { root, app };
}

function byTestId<T extends Element = HTMLElement>(root: ParentNode, id: string): T {
  return root.querySelector<T>(`[data-testid="${id}"]`)!;
}

function setValue(element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement, value: string) {
  element.value = value;
  element.dispatchEvent(new Event(element instanceof HTMLSelectElement ? "change" : "input"));
}

describe("audit panels", () => {
  let requests: { path: string; body: any }[];
  let sessions: typeof SESSIONS;

  beforeEach(() => {
    requests = [];
    sessions = [...SESSIONS];
    vi.stubGlobal("confirm", () => true);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input).split("/api/")[1];
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        requests.push({ path, body });
        if (path === "connection/list") return jsonResponse([{ id: "c-sales", name: "Sales" }]);
        if (path === "admin/users/list") return jsonResponse([{ id: "u-ana", username: "ana", display_name: null, role: "user", active: true }]);
        if (path === "admin/audit/list") {
          if (body.decision === "maybe") return jsonResponse({ error: "audit_filter_invalid" }, 400);
          return body.before_id ? jsonResponse({ entries: [SYSTEM_EVENT], next_before_id: null, dropped_events: 0 }) : jsonResponse({ entries: [SQL_EVENT], next_before_id: 7, dropped_events: 3 });
        }
        if (path === "admin/audit/reveal") return jsonResponse({ event_id: body.event_id, statement: "DELETE FROM orders" });
        if (path === "admin/audit/export") return jsonResponse("id,event_id\n7,e-7\n", 200, { "content-disposition": 'attachment; filename="dbx-audit-1.csv"', "x-dbx-export-truncated": "true" });
        if (path === "admin/sessions/list") return jsonResponse(sessions);
        if (path === "admin/sessions/revoke") {
          sessions = sessions.filter((session) => (body.id ? session.id !== body.id : session.user_id !== body.user_id));
          return jsonResponse({ revoked: 1 });
        }
        return jsonResponse({ ok: true });
      }),
    );
    URL.createObjectURL = vi.fn(() => "blob:audit");
    URL.revokeObjectURL = vi.fn();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("should show audit events with actor, target and decision", async () => {
    const { root, app } = mount(AuditLogPanel);
    await flush();
    const entries = root.querySelectorAll('[data-testid="audit-entry"]');
    expect(entries).toHaveLength(1);
    expect(entries[0].textContent).toContain("audit.events.sql");
    expect(entries[0].textContent).toContain("ana");
    expect(entries[0].textContent).toContain("Sales / crm / orders");
    expect(entries[0].textContent).toContain("DELETE");
    expect(entries[0].textContent).toContain("audit.denied");
    expect(root.textContent).toContain('audit.droppedEvents:{"count":3}');
    expect(requests.find((request) => request.path === "admin/audit/list")?.body).toEqual({ limit: 50 });
    app.unmount();
  });

  it("should send the filters and page with the cursor", async () => {
    const { root, app } = mount(AuditLogPanel);
    await flush();
    setValue(byTestId<HTMLSelectElement>(root, "audit-user"), "u-ana");
    setValue(byTestId<HTMLSelectElement>(root, "audit-decision"), "deny");
    setValue(byTestId<HTMLSelectElement>(root, "audit-event"), "sql");
    setValue(byTestId<HTMLInputElement>(root, "audit-from"), "2026-11-01");
    setValue(byTestId<HTMLTextAreaElement>(root, "audit-statement"), "  DELETE FROM orders ");
    await flush();
    byTestId<HTMLFormElement>(root, "audit-filters").dispatchEvent(new Event("submit"));
    await flush();
    const searched = requests.filter((request) => request.path === "admin/audit/list").at(-1)!.body;
    expect(searched).toEqual({ user_id: "u-ana", decision: "deny", event: "sql", from: startOfDay("2026-11-01"), statement: "DELETE FROM orders", limit: 50 });

    byTestId<HTMLButtonElement>(root, "audit-more").click();
    await flush();
    expect(requests.filter((request) => request.path === "admin/audit/list").at(-1)!.body.before_id).toBe(7);
    expect(root.querySelectorAll('[data-testid="audit-entry"]')).toHaveLength(2);
    expect(root.textContent).toContain('audit.systemTask:{"task":"backup:run-1"}');
    expect(root.querySelector('[data-testid="audit-more"]')).toBeNull();
    app.unmount();
  });

  it("should reveal the encrypted statement only on demand", async () => {
    const { root, app } = mount(AuditLogPanel);
    await flush();
    root.querySelector<HTMLButtonElement>('[data-testid="audit-entry"] button')!.click();
    await flush();
    const detail = byTestId(root, "audit-entry-detail");
    expect(detail.textContent).toContain("10.0.0.7");
    expect(detail.textContent).toContain("audit.statementEncrypted");
    expect(requests.some((request) => request.path === "admin/audit/reveal")).toBe(false);
    byTestId<HTMLButtonElement>(detail, "audit-reveal").click();
    await flush();
    expect(requests.find((request) => request.path === "admin/audit/reveal")?.body).toEqual({ event_id: "e-7" });
    expect(byTestId(root, "audit-statement-text").textContent).toBe("DELETE FROM orders");
    app.unmount();
  });

  it("should export with statements only when asked and report truncation", async () => {
    const { root, app } = mount(AuditLogPanel);
    await flush();
    const include = byTestId<HTMLInputElement>(root, "audit-include-statements");
    include.checked = true;
    include.dispatchEvent(new Event("change"));
    await flush();
    byTestId<HTMLButtonElement>(root, "audit-export").click();
    await flush();
    expect(requests.find((request) => request.path === "admin/audit/export")?.body).toEqual({ include_statements: true });
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(root.textContent).toContain("audit.exportTruncated");
    app.unmount();
  });

  it("should translate backend errors from the audit api", async () => {
    const { root, app } = mount(AuditLogPanel);
    await flush();
    const decision = byTestId<HTMLSelectElement>(root, "audit-decision");
    const option = document.createElement("option");
    option.value = "maybe";
    decision.append(option);
    setValue(decision, "maybe");
    await flush();
    byTestId<HTMLFormElement>(root, "audit-filters").dispatchEvent(new Event("submit"));
    await flush();
    expect(byTestId(root, "audit-log").textContent).toContain("audit.errors.filterInvalid");
    app.unmount();
  });

  it("should group sessions by user and never offer to revoke the current one", async () => {
    const { root, app } = mount(SessionsPanel);
    await flush();
    const users = root.querySelectorAll('[data-testid="sessions-user"]');
    expect(users).toHaveLength(2);
    expect(users[0].textContent).toContain("admin");
    expect(users[0].querySelector('[data-testid="session-revoke"]')).toBeNull();
    expect(users[0].querySelector('[data-testid="sessions-revoke-all"]')).toBeNull();
    expect(users[1].querySelectorAll('[data-testid="session-row"]')).toHaveLength(2);

    users[1].querySelector<HTMLButtonElement>('[data-testid="session-revoke"]')!.click();
    await flush();
    expect(requests.find((request) => request.path === "admin/sessions/revoke")?.body).toEqual({ id: "h-ana-1" });
    expect(root.querySelectorAll('[data-testid="session-row"]')).toHaveLength(2);

    root.querySelector<HTMLButtonElement>('[data-testid="sessions-revoke-all"]')!.click();
    await flush();
    expect(requests.filter((request) => request.path === "admin/sessions/revoke").at(-1)!.body).toEqual({ user_id: "u-ana" });
    expect(root.querySelectorAll('[data-testid="sessions-user"]')).toHaveLength(1);
    app.unmount();
  });
});

describe("auditAdmin helpers", () => {
  it("should drop empty filters and trim text", () => {
    expect(cleanQuery({ user_id: "", event: " sql ", from: undefined, limit: 50, include_statements: false })).toEqual({ event: "sql", limit: 50, include_statements: false });
  });

  it("should cover whole local days", () => {
    const start = new Date(startOfDay("2026-11-12")!);
    const end = new Date(endOfDayMillis("2026-11-12")!);
    expect([start.getHours(), start.getMinutes()]).toEqual([0, 0]);
    expect([end.getHours(), end.getMinutes(), end.getSeconds(), end.getMilliseconds()]).toEqual([23, 59, 59, 999]);
    expect(startOfDay("")).toBeUndefined();
  });
});
