// @vitest-environment happy-dom

import { createApp, defineComponent, h, nextTick, provide, ref, type App, type Component } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({
    t: (key: string, values?: Record<string, unknown>) => (values ? `${key}:${JSON.stringify(values)}` : key),
    te: (key: string) => key.startsWith("audit.events."),
    locale: ref("en"),
  }),
}));

import AuditSection from "../activity/AuditSection.vue";
import SessionsSection from "../activity/SessionsSection.vue";
import IdentityProvidersSection from "../authentication/IdentityProvidersSection.vue";
import PoliciesSection from "../authentication/PoliciesSection.vue";
import { ADMIN_CONFIRM } from "@/lib/auth/adminConfirm";
import { ADMIN_DIRECTORY, createAdminDirectory } from "@/lib/auth/adminDirectory";
import { ADMIN_NAVIGATOR } from "@/lib/auth/adminNavigation";
import { startOfDay } from "@/lib/auth/auditAdmin";

const USERS = [
  { id: "u-admin", username: "admin", display_name: null, role: "admin", active: true, mfa_enabled: true, mfa_required: false },
  { id: "u-ana", username: "ana", display_name: "Ana", role: "user", active: true, mfa_enabled: false, mfa_required: true },
];
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
  rows_affected: 4,
  duration_ms: 12,
  detail: null,
};
const SYSTEM_EVENT = { ...SQL_EVENT, id: 6, event_id: "e-6", acting_principal: "system", task_id: "backup:run-1", username: null, user_id: null, decision: "allow", has_statement: false, operations: ["SELECT", "EXPORT"], event: "data_access" };
const SESSIONS = [
  { id: "h-admin", session_ref: "h-admin", user_id: "u-admin", username: "admin", created_at: 1, last_seen_at: 2, expires_at: null, ip: "127.0.0.1", user_agent: "Firefox", current: true },
  { id: "h-ana-1", session_ref: "h-ana-1", user_id: "u-ana", username: "ana", created_at: 1, last_seen_at: 3, expires_at: 5, ip: "10.0.0.7", user_agent: null, current: false },
  { id: "h-ana-2", session_ref: "h-ana-2", user_id: "u-ana", username: "ana", created_at: 1, last_seen_at: 2, expires_at: 5, ip: "10.0.0.8", user_agent: "Chrome", current: false },
];

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

async function flush() {
  for (let i = 0; i < 20; i += 1) {
    await Promise.resolve();
    await nextTick();
  }
}

const navigated: unknown[] = [];

async function mount(component: Component, props: Record<string, unknown> = {}): Promise<{ root: HTMLElement; app: App }> {
  const directory = createAdminDirectory(ref("u-admin"));
  await directory.refresh();
  const Wrapper = defineComponent({
    setup() {
      provide(ADMIN_DIRECTORY, directory);
      provide(ADMIN_CONFIRM, async () => true);
      provide(ADMIN_NAVIGATOR, { go: (route: unknown) => navigated.push(route) });
      return () => h(component, props);
    },
  });
  const root = document.createElement("div");
  document.body.append(root);
  const app = createApp(Wrapper);
  app.mount(root);
  await flush();
  return { root, app };
}

function byTestId<T extends Element = HTMLElement>(root: ParentNode, id: string): T {
  return root.querySelector<T>(`[data-testid="${id}"]`)!;
}

function setValue(element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement, value: string) {
  element.value = value;
  element.dispatchEvent(new Event(element instanceof HTMLSelectElement ? "change" : "input"));
}

async function chooseRowAction(row: Element, key: string) {
  row.querySelector<HTMLButtonElement>('[data-testid="admin-row-menu"]')!.click();
  await flush();
  document.querySelector<HTMLElement>(`[data-testid="admin-action-${key}"]`)!.click();
  await flush();
}

describe("admin console activity and authentication", () => {
  let requests: { path: string; body: any }[];
  let sessions: typeof SESSIONS;

  beforeEach(() => {
    (window as unknown as { happyDOM: { setURL: (url: string) => void } }).happyDOM.setURL("http://localhost:4224/");
    requests = [];
    navigated.length = 0;
    sessions = [...SESSIONS];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input).split("/api/")[1];
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        requests.push({ path, body });
        if (path === "connection/list") return jsonResponse([{ id: "c-sales", name: "Sales" }]);
        if (path === "admin/users/list") return jsonResponse(USERS);
        if (path === "admin/groups/list") return jsonResponse([{ id: "g1", name: "Engineers", description: null, member_ids: [] }]);
        if (path === "admin/roles/list") return jsonResponse([]);
        if (path === "admin/audit/list") {
          if (body.decision === "maybe") return jsonResponse({ error: "audit_filter_invalid" }, 400);
          return body.before_id ? jsonResponse({ entries: [SYSTEM_EVENT], next_before_id: null, dropped_events: 0 }) : jsonResponse({ entries: [SQL_EVENT], next_before_id: 7, dropped_events: 3 });
        }
        if (path === "admin/audit/reveal") return jsonResponse({ event_id: body.event_id, statement: "DELETE FROM orders" });
        if (path === "admin/audit/export") return jsonResponse("id,event_id\n7,e-7\n", 200, { "content-disposition": 'attachment; filename="dbx-audit-1.csv"', "x-dbx-export-truncated": "true" });
        if (path === "admin/sessions/list") return jsonResponse(body?.user_id ? sessions.filter((session) => session.user_id === body.user_id) : sessions);
        if (path === "admin/sessions/revoke") {
          sessions = sessions.filter((session) => (body.id ? session.id !== body.id : session.user_id !== body.user_id));
          return jsonResponse({ revoked: 1 });
        }
        if (path === "admin/identity-providers/list") return jsonResponse([]);
        if (path === "admin/identity-providers/save") return jsonResponse({ ...body, id: "new", has_secret: true });
        if (path === "admin/users/mfa-policy") return jsonResponse({ required_all: false });
        if (path === "admin/users/mfa-policy/save") return jsonResponse({ required_all: body.required_all });
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
    const { root, app } = await mount(AuditSection);
    const rows = root.querySelectorAll('[data-testid="audit-entry-row"]');
    expect(rows).toHaveLength(1);
    expect(rows[0].textContent).toContain("audit.events.sql");
    expect(rows[0].textContent).toContain("ana");
    expect(rows[0].textContent).toContain("Sales / crm / orders");
    expect(rows[0].textContent).toContain("DELETE");
    expect(rows[0].textContent).toContain("audit.denied");
    expect(root.textContent).toContain('audit.droppedEvents:{"count":3}');
    expect(requests.find((request) => request.path === "admin/audit/list")?.body).toEqual({ limit: 50 });
    app.unmount();
  });

  it("should send the filters and move between pages with the cursor stack", async () => {
    const { root, app } = await mount(AuditSection);
    setValue(byTestId<HTMLSelectElement>(root, "audit-user"), "u-ana");
    setValue(byTestId<HTMLSelectElement>(root, "audit-decision"), "deny");
    setValue(byTestId<HTMLSelectElement>(root, "audit-event"), "sql");
    setValue(byTestId<HTMLInputElement>(root, "audit-from"), "2026-11-01");
    setValue(byTestId<HTMLTextAreaElement>(root, "audit-statement"), "  DELETE FROM orders ");
    await flush();
    byTestId<HTMLFormElement>(root, "audit-filters").dispatchEvent(new Event("submit"));
    await flush();
    const listed = () => requests.filter((request) => request.path === "admin/audit/list");
    expect(listed().at(-1)!.body).toEqual({ user_id: "u-ana", decision: "deny", event: "sql", from: startOfDay("2026-11-01"), statement: "DELETE FROM orders", limit: 50 });
    expect(byTestId<HTMLButtonElement>(root, "audit-previous").disabled).toBe(true);

    byTestId<HTMLButtonElement>(root, "audit-next").click();
    await flush();
    expect(listed().at(-1)!.body.before_id).toBe(7);
    expect(byTestId(root, "audit-page").textContent).toContain('"page":2');
    expect(root.textContent).toContain('audit.systemTask:{"task":"backup:run-1"}');
    expect(byTestId<HTMLButtonElement>(root, "audit-next").disabled).toBe(true);

    byTestId<HTMLButtonElement>(root, "audit-previous").click();
    await flush();
    expect(listed().at(-1)!.body.before_id).toBeUndefined();
    expect(byTestId(root, "audit-page").textContent).toContain('"page":1');
    expect(root.querySelectorAll('[data-testid="audit-entry-row"]')).toHaveLength(1);

    setValue(byTestId<HTMLSelectElement>(root, "audit-page-size"), "100");
    await flush();
    expect(listed().at(-1)!.body.limit).toBe(100);
    app.unmount();
  });

  it("should reveal the encrypted statement only on demand", async () => {
    const { root, app } = await mount(AuditSection);
    root.querySelector<HTMLElement>('[data-testid="audit-entry-row"]')!.click();
    await flush();
    const detail = byTestId(document, "audit-entry-detail");
    expect(detail.textContent).toContain("10.0.0.7");
    expect(byTestId(detail, "audit-rows").textContent).toBe("4");
    expect(detail.textContent).toContain('audit.durationMs:{"ms":12}');
    expect(detail.textContent).toContain("audit.statementEncrypted");
    expect(requests.some((request) => request.path === "admin/audit/reveal")).toBe(false);
    byTestId<HTMLButtonElement>(detail, "audit-reveal").click();
    await flush();
    expect(requests.find((request) => request.path === "admin/audit/reveal")?.body).toEqual({ event_id: "e-7" });
    expect(byTestId(document, "audit-statement-text").textContent).toBe("DELETE FROM orders");
    app.unmount();
  });

  it("should export with statements only when asked and report truncation", async () => {
    const { root, app } = await mount(AuditSection);
    const include = byTestId<HTMLInputElement>(root, "audit-include-statements");
    include.checked = true;
    include.dispatchEvent(new Event("change"));
    await flush();
    byTestId<HTMLButtonElement>(root, "audit-export").click();
    await flush();
    expect(requests.find((request) => request.path === "admin/audit/export")?.body).toEqual({ include_statements: true });
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(byTestId(root, "audit-notice").textContent).toContain("audit.exportTruncated");
    app.unmount();
  });

  it("should scope the embedded audit log to one user", async () => {
    const { root, app } = await mount(AuditSection, { userId: "u-ana", embedded: true });
    expect(requests.find((request) => request.path === "admin/audit/list")?.body).toEqual({ user_id: "u-ana", limit: 50 });
    expect(root.querySelector('[data-testid="audit-user"]')).toBeNull();
    app.unmount();
  });

  it("should translate backend errors from the audit api", async () => {
    const { root, app } = await mount(AuditSection);
    const decision = byTestId<HTMLSelectElement>(root, "audit-decision");
    const option = document.createElement("option");
    option.value = "maybe";
    decision.append(option);
    setValue(decision, "maybe");
    await flush();
    byTestId<HTMLFormElement>(root, "audit-filters").dispatchEvent(new Event("submit"));
    await flush();
    expect(byTestId(root, "audit-error").textContent).toContain("audit.errors.filterInvalid");
    app.unmount();
  });

  it("should list sessions, keep the current one and revoke the others", async () => {
    const { root, app } = await mount(SessionsSection);
    const rows = () => [...root.querySelectorAll('[data-testid="admin-sessions-table-row"]')];
    expect(rows()).toHaveLength(3);
    const current = rows().find((row) => row.querySelector('[data-testid="session-current"]'))!;
    expect(current.textContent).toContain("127.0.0.1");
    expect(current.querySelector('[data-testid="admin-row-menu"]')).toBeNull();
    expect(root.querySelector('[data-testid="sessions-revoke-all"]')).toBeNull();

    const anaRow = rows().find((row) => row.textContent?.includes("10.0.0.7"))!;
    await chooseRowAction(anaRow, "revoke");
    expect(requests.find((request) => request.path === "admin/sessions/revoke")?.body).toEqual({ id: "h-ana-1" });
    expect(rows()).toHaveLength(2);

    setValue(byTestId<HTMLSelectElement>(root, "admin-sessions-user-filter"), "u-ana");
    await flush();
    expect(rows()).toHaveLength(1);
    byTestId<HTMLButtonElement>(root, "sessions-revoke-all").click();
    await flush();
    expect(requests.filter((request) => request.path === "admin/sessions/revoke").at(-1)!.body).toEqual({ user_id: "u-ana" });
    app.unmount();
  });

  it("should show only the user's sessions when embedded in the user page", async () => {
    const { root, app } = await mount(SessionsSection, { userId: "u-ana", embedded: true });
    expect(requests.find((request) => request.path === "admin/sessions/list")?.body).toEqual({ user_id: "u-ana" });
    const rows = root.querySelectorAll('[data-testid="admin-sessions-table-row"]');
    expect(rows).toHaveLength(2);
    expect(root.textContent).not.toContain("127.0.0.1");
    expect(root.querySelector('[data-testid="admin-sessions-user-filter"]')).toBeNull();
    expect(root.querySelector('[data-testid="sessions-revoke-all"]')).not.toBeNull();
    app.unmount();
  });

  it("should open a user from the sessions table", async () => {
    const { root, app } = await mount(SessionsSection);
    const row = [...root.querySelectorAll('[data-testid="admin-sessions-table-row"]')].find((candidate) => candidate.textContent?.includes("10.0.0.8"))!;
    row.querySelector<HTMLButtonElement>("button")!.click();
    await flush();
    expect(navigated).toEqual([{ section: "user", id: "u-ana" }]);
    app.unmount();
  });

  it("should create an OpenID Connect provider with its secret and switch fields for LDAP", async () => {
    const { root, app } = await mount(IdentityProvidersSection);
    expect(root.textContent).toContain("adminConsole.identity.empty");
    byTestId<HTMLButtonElement>(root, "identity-provider-new").click();
    await flush();
    expect(byTestId<HTMLInputElement>(document, "identity-provider-redirect_uri").value).toContain("/api/auth/oidc/callback");
    setValue(byTestId<HTMLInputElement>(document, "identity-provider-name"), " Keycloak ");
    setValue(byTestId<HTMLInputElement>(document, "identity-provider-issuer"), "https://id.example.com/realms/dbx");
    setValue(byTestId<HTMLInputElement>(document, "identity-provider-client_id"), "dbx");
    setValue(byTestId<HTMLInputElement>(document, "identity-provider-secret"), "s3cret");
    const autoCreate = byTestId<HTMLInputElement>(document, "identity-provider-auto-create");
    autoCreate.checked = true;
    autoCreate.dispatchEvent(new Event("change"));
    await flush();
    setValue(byTestId<HTMLSelectElement>(document, "identity-provider-default-group"), "g1");
    await flush();
    byTestId<HTMLFormElement>(document, "identity-provider-form").dispatchEvent(new Event("submit"));
    await flush();
    const saved = requests.find((request) => request.path === "admin/identity-providers/save")!.body;
    expect(saved).toMatchObject({ kind: "oidc", name: "Keycloak", auto_create_users: true, secret: "s3cret", default_group_id: "g1", enabled: true });
    expect(saved.config).toMatchObject({ issuer: "https://id.example.com/realms/dbx", client_id: "dbx", token_auth: "basic" });
    expect(requests.filter((request) => request.path === "admin/identity-providers/list")).toHaveLength(2);

    byTestId<HTMLButtonElement>(root, "identity-provider-new").click();
    await flush();
    setValue(byTestId<HTMLSelectElement>(document, "identity-provider-kind"), "ldap");
    await flush();
    expect(document.querySelector('[data-testid="identity-provider-url"]')).not.toBeNull();
    expect(document.querySelector('[data-testid="identity-provider-issuer"]')).toBeNull();
    app.unmount();
  });

  it("should require two-step sign-in for everyone and refresh the users", async () => {
    const { root, app } = await mount(PoliciesSection);
    expect(requests.some((request) => request.path === "admin/users/mfa-policy")).toBe(true);
    const usersLoads = requests.filter((request) => request.path === "admin/users/list").length;
    byTestId<HTMLButtonElement>(root, "mfa-required-all").click();
    await flush();
    expect(requests.find((request) => request.path === "admin/users/mfa-policy/save")?.body).toEqual({ required_all: true });
    expect(requests.filter((request) => request.path === "admin/users/list").length).toBe(usersLoads + 1);
    expect(byTestId(root, "mfa-required-all").getAttribute("aria-checked")).toBe("true");
    expect(byTestId(root, "admin-policies-mfa").textContent).toContain("1");
    app.unmount();
  });
});
