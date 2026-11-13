// @vitest-environment happy-dom

import { createApp, nextTick, ref, type App } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string, values?: Record<string, unknown>) => (values ? `${key}:${JSON.stringify(values)}` : key), locale: ref("en") }),
}));

import AccessControlPanel from "../access/AccessControlPanel.vue";
import { describeResource, endOfDay } from "@/lib/auth/accessAdmin";

const ADMIN = { id: "u-admin", username: "admin", display_name: null, role: "admin", active: true };
const ANA = { id: "u-ana", username: "ana", display_name: "Ana", role: "user", active: true };
const ANALYSTS = { id: "g-analysts", name: "Analysts", description: null, member_ids: ["u-ana"] };
const ROLES = [
  { id: "builtin:reader", name: "reader", operations: ["SELECT", "EXPORT"], builtin: true, description: null },
  { id: "r-custom", name: "Loader", operations: ["SELECT", "INSERT"], builtin: false, description: null },
];
const CONNECTIONS = [
  { id: "c-sales", name: "Sales" },
  { id: "c-hr", name: "HR" },
];
const GRANTS = [
  { id: "g1", subject: { kind: "group", id: "g-analysts" }, scope: { kind: "resource", value: { connectionId: "c-sales", database: "crm" } }, effect: "allow", operations: null, role_id: "builtin:reader", expires_at: null, note: null },
  { id: "g2", subject: { kind: "user", id: "u-ana" }, scope: { kind: "resource", value: { connectionId: "c-hr" } }, effect: "deny", operations: ["DELETE"], role_id: null, expires_at: null, note: "no deletes" },
];

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function flush() {
  for (let i = 0; i < 16; i += 1) {
    await Promise.resolve();
    await nextTick();
  }
}

function mount(): { root: HTMLElement; app: App } {
  const root = document.createElement("div");
  document.body.append(root);
  const app = createApp(AccessControlPanel);
  app.mount(root);
  return { root, app };
}

function setValue(element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement, value: string) {
  element.value = value;
  element.dispatchEvent(new Event(element instanceof HTMLSelectElement ? "change" : "input"));
}

function check(root: ParentNode, value: string, checked: boolean) {
  const box = root.querySelector<HTMLInputElement>(`input[type="checkbox"][value="${value}"]`)!;
  box.checked = checked;
  box.dispatchEvent(new Event("change"));
}

function byTestId<T extends Element = HTMLElement>(root: ParentNode, id: string): T {
  return root.querySelector<T>(`[data-testid="${id}"]`)!;
}

async function openSection(root: HTMLElement, section: string) {
  byTestId(root, `access-tab-${section}`).click();
  await flush();
}

describe("AccessControlPanel", () => {
  let requests: { path: string; body: any }[];
  let grantResponse: () => Response;
  let grantList: unknown[];

  beforeEach(() => {
    requests = [];
    grantResponse = () => jsonResponse({ ...GRANTS[0], id: "g-new" });
    grantList = GRANTS;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input).split("/api/")[1];
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        requests.push({ path, body });
        if (path === "connection/list") return jsonResponse(CONNECTIONS);
        if (path === "admin/users/list") return jsonResponse([ADMIN, ANA]);
        if (path === "admin/groups/list") return jsonResponse([ANALYSTS]);
        if (path === "admin/roles/list") return jsonResponse(ROLES);
        if (path === "admin/grants/list") return jsonResponse(grantList);
        if (path === "admin/grants/delete") {
          grantList = (grantList as { id: string }[]).filter((grant) => grant.id !== body.id);
          return jsonResponse({ ok: true });
        }
        if (path === "admin/grants/save") return grantResponse();
        if (path === "admin/grants/effective")
          return jsonResponse({
            visible: true,
            implicit_admin: false,
            connection_operations: [],
            rules: [{ grant_id: "g1", via_group: "g-analysts", resource: { connectionId: "c-sales", database: "crm" }, effect: "allow", operations: ["SELECT", "EXPORT"] }],
          });
        if (path === "admin/connection-policies/list") return jsonResponse([{ connection_id: "c-sales", strict_function_mode: true, function_allowlist: ["app.safe"] }]);
        if (path === "admin/connection-policies/save") return jsonResponse({ ...body, function_allowlist: [...body.function_allowlist].map((name: string) => name.toLowerCase()).sort() });
        if (path === "admin/groups/create") return jsonResponse({ id: "g-new", name: body.name, description: null, member_ids: [] }, 201);
        return jsonResponse({ ok: true });
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("should list grants with readable subjects, scopes and permissions", async () => {
    const { root, app } = mount();
    await flush();
    const rows = root.querySelectorAll('[data-testid="access-grant"]');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('access.subjectGroup:{"name":"Analysts"}');
    expect(rows[0].textContent).toContain("Sales / crm");
    expect(rows[0].textContent).toContain("access.builtinRoles.reader");
    expect(rows[1].textContent).toContain("access.deny");
    expect(rows[1].textContent).toContain("DELETE");
    expect(rows[1].textContent).toContain("no deletes");

    setValue(byTestId<HTMLSelectElement>(root, "grant-filter"), "c-hr");
    await flush();
    expect(root.querySelectorAll('[data-testid="access-grant"]')).toHaveLength(1);
    app.unmount();
  });

  it("should save a grant with explicit operations on a database", async () => {
    const { root, app } = mount();
    await flush();
    const form = byTestId(root, "grant-form");
    setValue(byTestId<HTMLSelectElement>(form, "grant-subject"), "u-ana");
    setValue(byTestId<HTMLSelectElement>(form, "grant-connection"), "c-sales");
    setValue(byTestId<HTMLInputElement>(form, "grant-database"), " crm ");
    setValue(byTestId<HTMLSelectElement>(form, "grant-mode"), "operations");
    await flush();
    check(form, "INSERT", true);
    await flush();
    check(form, "UPDATE", true);
    await flush();
    byTestId<HTMLButtonElement>(form, "grant-save").click();
    await flush();

    const saved = requests.find((request) => request.path === "admin/grants/save");
    expect(saved?.body).toEqual({
      subject: { kind: "user", id: "u-ana" },
      scope: { kind: "resource", value: { connectionId: "c-sales", database: "crm" } },
      effect: "allow",
      operations: ["SELECT", "INSERT", "UPDATE"],
      role_id: null,
      expires_at: null,
      note: null,
    });
    expect(requests.filter((request) => request.path === "admin/grants/list")).toHaveLength(2);
    app.unmount();
  });

  it("should require a database before narrowing to a schema", async () => {
    const { root, app } = mount();
    await flush();
    const form = byTestId(root, "grant-form");
    setValue(byTestId<HTMLSelectElement>(form, "grant-subject"), "u-ana");
    setValue(byTestId<HTMLSelectElement>(form, "grant-connection"), "c-sales");
    setValue(form.querySelector<HTMLInputElement>('input[placeholder="access.schemaAny"]')!, "public");
    await flush();
    expect(byTestId<HTMLButtonElement>(form, "grant-save").disabled).toBe(true);
    app.unmount();
  });

  it("should show the translated backend error when a grant is rejected", async () => {
    grantResponse = () => jsonResponse({ error: "subject_not_found" }, 404);
    const { root, app } = mount();
    await flush();
    const form = byTestId(root, "grant-form");
    setValue(byTestId<HTMLSelectElement>(form, "grant-subject-kind"), "system");
    await flush();
    setValue(byTestId<HTMLSelectElement>(form, "grant-connection"), "c-hr");
    await flush();
    byTestId<HTMLButtonElement>(form, "grant-save").click();
    await flush();
    expect(requests.find((request) => request.path === "admin/grants/save")?.body.subject).toEqual({ kind: "system" });
    expect(byTestId(root, "access-grants").textContent).toContain("access.errors.subjectNotFound");
    app.unmount();
  });

  it("should mark expired grants and remove them together", async () => {
    vi.stubGlobal("confirm", () => true);
    grantList = [...GRANTS, { ...GRANTS[1], id: "g-old", expires_at: Date.now() - 86_400_000, note: null }];
    const { root, app } = mount();
    await flush();
    const rows = root.querySelectorAll('[data-testid="access-grant"]');
    expect(rows).toHaveLength(3);
    expect(rows[2].querySelector('[data-testid="grant-expired"]')).not.toBeNull();
    expect(rows[2].className).toContain("opacity-60");
    expect(rows[0].querySelector('[data-testid="grant-expired"]')).toBeNull();
    expect(byTestId(root, "grant-expired-summary").textContent).toContain('access.expiredCount:{"count":1}');

    byTestId<HTMLButtonElement>(root, "grant-remove-expired").click();
    await flush();
    expect(requests.filter((request) => request.path === "admin/grants/delete").map((request) => request.body)).toEqual([{ id: "g-old" }]);
    expect(root.querySelectorAll('[data-testid="access-grant"]')).toHaveLength(2);
    expect(root.querySelector('[data-testid="grant-expired-summary"]')).toBeNull();
    app.unmount();
  });

  it("should not save a grant that would already be expired", async () => {
    const { root, app } = mount();
    await flush();
    const form = byTestId(root, "grant-form");
    setValue(byTestId<HTMLSelectElement>(form, "grant-subject"), "u-ana");
    setValue(byTestId<HTMLSelectElement>(form, "grant-connection"), "c-sales");
    await flush();
    expect(byTestId<HTMLButtonElement>(form, "grant-save").disabled).toBe(false);
    setValue(byTestId<HTMLInputElement>(form, "grant-expires"), "2020-01-01");
    await flush();
    expect(byTestId<HTMLButtonElement>(form, "grant-save").disabled).toBe(true);
    expect(byTestId(form, "grant-expiry-past").textContent).toContain("access.expiryInPast");
    app.unmount();
  });

  it("should create a group and reload the shared data", async () => {
    const { root, app } = mount();
    await flush();
    await openSection(root, "groups");
    expect(byTestId(root, "access-group").textContent).toContain("ana");
    setValue(byTestId<HTMLInputElement>(root, "new-group-name"), "  Support ");
    await flush();
    root.querySelector<HTMLFormElement>('[data-testid="access-groups"] form')!.dispatchEvent(new Event("submit"));
    await flush();
    expect(requests.find((request) => request.path === "admin/groups/create")?.body).toEqual({ name: "Support", description: null });
    expect(requests.filter((request) => request.path === "admin/groups/list")).toHaveLength(2);
    app.unmount();
  });

  it("should only allow editing custom roles", async () => {
    const { root, app } = mount();
    await flush();
    await openSection(root, "roles");
    const rows = root.querySelectorAll('[data-testid="access-role"]');
    expect(rows[0].querySelectorAll("button")).toHaveLength(0);
    expect(rows[1].querySelectorAll("button")).toHaveLength(2);
    app.unmount();
  });

  it("should explain effective permissions including the group they come from", async () => {
    const { root, app } = mount();
    await flush();
    await openSection(root, "effective");
    setValue(byTestId<HTMLSelectElement>(root, "effective-user"), "u-ana");
    setValue(byTestId<HTMLSelectElement>(root, "effective-connection"), "c-sales");
    await flush();
    expect(requests.find((request) => request.path === "admin/grants/effective")?.body).toEqual({ user_id: "u-ana", connection_id: "c-sales" });
    expect(byTestId(root, "effective-operations").textContent).toBe("access.none");
    const rule = byTestId(root, "effective-rule");
    expect(rule.textContent).toContain("Sales / crm");
    expect(rule.textContent).toContain("SELECT · EXPORT");
    expect(rule.textContent).toContain('access.viaGroup:{"name":"Analysts"}');
    app.unmount();
  });

  it("should load and save the strict function policy of a connection", async () => {
    const { root, app } = mount();
    await flush();
    await openSection(root, "functions");
    setValue(byTestId<HTMLSelectElement>(root, "functions-connection"), "c-sales");
    await flush();
    expect(byTestId<HTMLInputElement>(root, "functions-strict").checked).toBe(true);
    expect(byTestId<HTMLTextAreaElement>(root, "functions-allowlist").value).toBe("app.safe");
    setValue(byTestId<HTMLTextAreaElement>(root, "functions-allowlist"), "app.safe\nAudit.Log, metrics.sum");
    await flush();
    root.querySelector<HTMLFormElement>('[data-testid="access-functions"] form')!.dispatchEvent(new Event("submit"));
    await flush();
    expect(requests.find((request) => request.path === "admin/connection-policies/save")?.body).toEqual({
      connection_id: "c-sales",
      strict_function_mode: true,
      function_allowlist: ["app.safe", "Audit.Log", "metrics.sum"],
    });
    expect(byTestId<HTMLTextAreaElement>(root, "functions-allowlist").value).toBe("app.safe\naudit.log\nmetrics.sum");
    expect(byTestId(root, "access-functions").textContent).toContain("access.saved");
    app.unmount();
  });
});

describe("accessAdmin helpers", () => {
  it("should describe a resource with the connection name", () => {
    expect(describeResource({ connectionId: "c-sales", database: "crm", schema: "public" }, CONNECTIONS)).toBe("Sales / crm / public");
    expect(describeResource({ connectionId: "c-gone" }, CONNECTIONS)).toBe("c-gone");
  });

  it("should turn a date into the end of that local day", () => {
    const millis = endOfDay("2026-12-31")!;
    const date = new Date(millis);
    expect([date.getFullYear(), date.getMonth(), date.getDate(), date.getHours(), date.getMinutes()]).toEqual([2026, 11, 31, 23, 59]);
    expect(endOfDay("")).toBeNull();
    expect(endOfDay("not-a-date")).toBeNull();
  });
});
