// @vitest-environment happy-dom

import { createApp, defineComponent, h, nextTick, onMounted, provide, ref, type App, type Component } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string, values?: Record<string, unknown>) => (values ? `${key}:${JSON.stringify(values)}` : key), te: () => true, locale: ref("en") }),
}));

import GrantsSection from "../grants/GrantsSection.vue";
import EffectiveSection from "../grants/EffectiveSection.vue";
import FunctionsSection from "../grants/FunctionsSection.vue";
import { ADMIN_CONFIRM } from "@/lib/auth/adminConfirm";
import { ADMIN_DIRECTORY, createAdminDirectory } from "@/lib/auth/adminDirectory";
import { ADMIN_NAVIGATOR } from "@/lib/auth/adminNavigation";

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
  for (let i = 0; i < 20; i += 1) {
    await Promise.resolve();
    await nextTick();
  }
}

const navigated: unknown[] = [];

function mount(component: Component, props: Record<string, unknown> = {}): { root: HTMLElement; app: App } {
  const root = document.createElement("div");
  document.body.append(root);
  const Wrapper = defineComponent({
    setup() {
      const directory = createAdminDirectory(ref("u-admin"));
      provide(ADMIN_DIRECTORY, directory);
      provide(ADMIN_CONFIRM, async () => true);
      provide(ADMIN_NAVIGATOR, { go: (route: unknown) => navigated.push(route) });
      onMounted(() => {
        void directory.refresh();
      });
      return () => h(component, props);
    },
  });
  const app = createApp(Wrapper);
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

function grantRows(root: ParentNode) {
  return root.querySelectorAll<HTMLElement>('[data-testid="access-grant-row"]');
}

async function openForm(root: HTMLElement): Promise<HTMLFormElement> {
  byTestId<HTMLButtonElement>(root, "grant-new").click();
  await flush();
  return byTestId<HTMLFormElement>(document.body, "grant-form");
}

async function submit(form: HTMLFormElement) {
  form.dispatchEvent(new Event("submit", { cancelable: true }));
  await flush();
}

describe("admin console permissions", () => {
  let requests: { path: string; body: any }[];
  let grantResponse: () => Response;
  let grantList: any[];

  beforeEach(() => {
    requests = [];
    navigated.length = 0;
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
        if (path === "admin/grants/list") {
          const subject = body?.subject;
          return jsonResponse(subject ? grantList.filter((grant) => grant.subject.kind === subject.kind && grant.subject.id === subject.id) : grantList);
        }
        if (path === "admin/grants/delete") {
          grantList = grantList.filter((grant) => grant.id !== body.id);
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
        return jsonResponse({ ok: true });
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("should list grants with readable subjects, scopes and permissions", async () => {
    const { root, app } = mount(GrantsSection);
    await flush();
    const rows = grantRows(root);
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('access.subjectGroup:{"name":"Analysts"}');
    expect(rows[0].textContent).toContain("Sales / crm");
    expect(rows[0].textContent).toContain("access.builtinRoles.reader");
    expect(rows[1].textContent).toContain("access.deny");
    expect(rows[1].textContent).toContain("DELETE");
    expect(rows[1].textContent).toContain("no deletes");

    setValue(byTestId<HTMLSelectElement>(root, "grant-filter"), "c-hr");
    await flush();
    expect(grantRows(root)).toHaveLength(1);

    setValue(byTestId<HTMLSelectElement>(root, "grant-filter"), "");
    setValue(byTestId<HTMLSelectElement>(root, "grant-effect-filter"), "allow");
    await flush();
    expect(grantRows(root)).toHaveLength(1);
    expect(grantRows(root)[0].textContent).toContain("Analysts");
    app.unmount();
  });

  it("should open the subject detail from the table", async () => {
    const { root, app } = mount(GrantsSection);
    await flush();
    byTestId<HTMLButtonElement>(grantRows(root)[1], "grant-subject-link").click();
    expect(navigated).toEqual([{ section: "user", id: "u-ana" }]);
    app.unmount();
  });

  it("should save a grant with explicit operations on a database", async () => {
    const { root, app } = mount(GrantsSection);
    await flush();
    const form = await openForm(root);
    setValue(byTestId<HTMLSelectElement>(form, "grant-subject"), "u-ana");
    setValue(byTestId<HTMLSelectElement>(form, "grant-connection"), "c-sales");
    setValue(byTestId<HTMLInputElement>(form, "grant-database"), " crm ");
    setValue(byTestId<HTMLSelectElement>(form, "grant-mode"), "operations");
    await flush();
    check(form, "INSERT", true);
    await flush();
    check(form, "UPDATE", true);
    await flush();
    expect(byTestId<HTMLButtonElement>(document.body, "grant-save").disabled).toBe(false);
    await submit(form);

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
    const { root, app } = mount(GrantsSection);
    await flush();
    const form = await openForm(root);
    setValue(byTestId<HTMLSelectElement>(form, "grant-subject"), "u-ana");
    setValue(byTestId<HTMLSelectElement>(form, "grant-connection"), "c-sales");
    setValue(byTestId<HTMLInputElement>(form, "grant-schema"), "public");
    await flush();
    expect(byTestId<HTMLButtonElement>(document.body, "grant-save").disabled).toBe(true);
    app.unmount();
  });

  it("should show the translated backend error when a grant is rejected", async () => {
    grantResponse = () => jsonResponse({ error: "subject_not_found" }, 404);
    const { root, app } = mount(GrantsSection);
    await flush();
    const form = await openForm(root);
    setValue(byTestId<HTMLSelectElement>(form, "grant-subject-kind"), "system");
    await flush();
    setValue(byTestId<HTMLSelectElement>(form, "grant-connection"), "c-hr");
    await flush();
    await submit(form);
    expect(requests.find((request) => request.path === "admin/grants/save")?.body.subject).toEqual({ kind: "system" });
    expect(byTestId(document.body, "grant-form-error").textContent).toContain("access.errors.subjectNotFound");
    app.unmount();
  });

  it("should warn that a deny always wins", async () => {
    const { root, app } = mount(GrantsSection);
    await flush();
    const form = await openForm(root);
    expect(byTestId(form, "grant-deny-hint")).toBeNull();
    setValue(byTestId<HTMLSelectElement>(form, "grant-effect"), "deny");
    await flush();
    expect(byTestId(form, "grant-deny-hint").textContent).toContain("access.denyHint");
    app.unmount();
  });

  it("should mark expired grants and remove them together", async () => {
    grantList = [...GRANTS, { ...GRANTS[1], id: "g-old", expires_at: Date.now() - 86_400_000, note: null }];
    const { root, app } = mount(GrantsSection);
    await flush();
    const rows = grantRows(root);
    expect(rows).toHaveLength(3);
    expect(rows[2].querySelector('[data-testid="grant-expired"]')).not.toBeNull();
    expect(rows[2].className).toContain("opacity-60");
    expect(rows[0].querySelector('[data-testid="grant-expired"]')).toBeNull();
    expect(byTestId(root, "grant-expired-summary").textContent).toContain('access.expiredCount:{"count":1}');

    byTestId<HTMLButtonElement>(root, "grant-remove-expired").click();
    await flush();
    expect(requests.filter((request) => request.path === "admin/grants/delete").map((request) => request.body)).toEqual([{ id: "g-old" }]);
    expect(grantRows(root)).toHaveLength(2);
    expect(root.querySelector('[data-testid="grant-expired-summary"]')).toBeNull();
    app.unmount();
  });

  it("should delete every selected grant", async () => {
    const { root, app } = mount(GrantsSection);
    await flush();
    for (const row of grantRows(root)) {
      const box = row.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
      box.checked = true;
      box.dispatchEvent(new Event("change"));
      await flush();
    }
    expect(byTestId(root, "grant-selection").textContent).toContain('adminConsole.table.selected:{"count":2}');
    byTestId<HTMLButtonElement>(root, "grant-delete-selected").click();
    await flush();
    expect(requests.filter((request) => request.path === "admin/grants/delete").map((request) => request.body)).toEqual([{ id: "g1" }, { id: "g2" }]);
    expect(grantRows(root)).toHaveLength(0);
    expect(root.querySelector('[data-testid="grant-selection"]')).toBeNull();
    app.unmount();
  });

  it("should not save a grant that would already be expired", async () => {
    const { root, app } = mount(GrantsSection);
    await flush();
    const form = await openForm(root);
    setValue(byTestId<HTMLSelectElement>(form, "grant-subject"), "u-ana");
    setValue(byTestId<HTMLSelectElement>(form, "grant-connection"), "c-sales");
    await flush();
    expect(byTestId<HTMLButtonElement>(document.body, "grant-save").disabled).toBe(false);
    setValue(byTestId<HTMLInputElement>(form, "grant-expires"), "2020-01-01");
    await flush();
    expect(byTestId<HTMLButtonElement>(document.body, "grant-save").disabled).toBe(true);
    expect(byTestId(form, "grant-expiry-past").textContent).toContain("access.expiryInPast");
    app.unmount();
  });

  it("should only list and grant to the embedded subject", async () => {
    const { root, app } = mount(GrantsSection, { subject: { kind: "user", id: "u-ana" }, embedded: true });
    await flush();
    expect(requests.find((request) => request.path === "admin/grants/list")?.body).toEqual({ subject: { kind: "user", id: "u-ana" } });
    expect(grantRows(root)).toHaveLength(1);
    expect(root.querySelector('[data-testid="grant-filter"]')).toBeNull();
    expect(root.querySelector('[data-testid="grant-subject-link"]')).toBeNull();

    const form = await openForm(root);
    expect(byTestId<HTMLSelectElement>(form, "grant-subject-kind").disabled).toBe(true);
    expect(byTestId<HTMLSelectElement>(form, "grant-subject").value).toBe("u-ana");
    setValue(byTestId<HTMLSelectElement>(form, "grant-connection"), "c-sales");
    await flush();
    await submit(form);
    expect(requests.find((request) => request.path === "admin/grants/save")?.body.subject).toEqual({ kind: "user", id: "u-ana" });
    app.unmount();
  });

  it("should explain effective permissions including the group they come from", async () => {
    const { root, app } = mount(EffectiveSection);
    await flush();
    setValue(byTestId<HTMLSelectElement>(root, "effective-user"), "u-ana");
    setValue(byTestId<HTMLSelectElement>(root, "effective-connection"), "c-sales");
    await flush();
    expect(requests.find((request) => request.path === "admin/grants/effective")?.body).toEqual({ user_id: "u-ana", connection_id: "c-sales" });
    expect(byTestId(root, "effective-visibility").textContent).toContain("access.visible");
    expect(byTestId(root, "effective-operations").textContent?.trim()).toBe("access.none");
    const rule = byTestId(root, "effective-rule-row");
    expect(rule.textContent).toContain("Sales / crm");
    expect(rule.textContent).toContain("SELECT · EXPORT");
    expect(rule.textContent).toContain('access.viaGroup:{"name":"Analysts"}');
    byTestId<HTMLButtonElement>(rule, "effective-via-group").click();
    expect(navigated).toEqual([{ section: "group", id: "g-analysts" }]);
    app.unmount();
  });

  it("should use the given user for effective permissions", async () => {
    const { root, app } = mount(EffectiveSection, { userId: "u-ana", embedded: true });
    await flush();
    expect(root.querySelector('[data-testid="effective-user"]')).toBeNull();
    setValue(byTestId<HTMLSelectElement>(root, "effective-connection"), "c-hr");
    await flush();
    expect(requests.find((request) => request.path === "admin/grants/effective")?.body).toEqual({ user_id: "u-ana", connection_id: "c-hr" });
    app.unmount();
  });

  it("should load and save the strict function policy of a connection", async () => {
    const { root, app } = mount(FunctionsSection);
    await flush();
    const rows = root.querySelectorAll<HTMLElement>('[data-testid="functions-connection-row"]');
    expect(rows).toHaveLength(2);
    const sales = [...rows].find((row) => row.textContent?.includes("Sales"))!;
    expect(byTestId(sales, "functions-mode").textContent).toContain("adminConsole.functions.strict");
    expect(byTestId(sales, "functions-count").textContent).toContain('{"count":1}');

    byTestId<HTMLButtonElement>(sales, "functions-edit").click();
    await flush();
    expect(byTestId(document.body, "functions-strict").getAttribute("aria-checked")).toBe("true");
    expect(byTestId<HTMLTextAreaElement>(document.body, "functions-allowlist").value).toBe("app.safe");
    setValue(byTestId<HTMLTextAreaElement>(document.body, "functions-allowlist"), "app.safe\nAudit.Log, metrics.sum");
    await flush();
    await submit(byTestId<HTMLFormElement>(document.body, "access-functions-form"));
    expect(requests.find((request) => request.path === "admin/connection-policies/save")?.body).toEqual({
      connection_id: "c-sales",
      strict_function_mode: true,
      function_allowlist: ["app.safe", "Audit.Log", "metrics.sum"],
    });
    const updated = [...root.querySelectorAll<HTMLElement>('[data-testid="functions-connection-row"]')].find((row) => row.textContent?.includes("Sales"))!;
    expect(byTestId(updated, "functions-count").textContent).toContain('{"count":3}');
    expect(byTestId(updated, "functions-saved").textContent).toContain("access.saved");
    app.unmount();
  });
});
