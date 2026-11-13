// @vitest-environment happy-dom

import { createApp, defineComponent, h, nextTick, provide, ref, type App, type Component } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string, values?: Record<string, unknown>) => (values ? `${key}:${JSON.stringify(values)}` : key), locale: ref("en") }),
}));

vi.mock("../grants/GrantsSection.vue", () => ({
  default: { name: "GrantsSectionStub", props: ["subject", "embedded"], render: () => null },
}));

import { ADMIN_CONFIRM } from "@/lib/auth/adminConfirm";
import { ADMIN_DIRECTORY, createAdminDirectory } from "@/lib/auth/adminDirectory";
import { ADMIN_NAVIGATOR, type AdminRoute } from "@/lib/auth/adminNavigation";
import GroupsSection from "../groups/GroupsSection.vue";
import GroupDetailPage from "../groups/GroupDetailPage.vue";
import RolesSection from "../roles/RolesSection.vue";

const ADMIN = { id: "u-admin", username: "admin", display_name: null, role: "admin", active: true };
const ANA = { id: "u-ana", username: "ana", display_name: "Ana", role: "user", active: true };
const BOB = { id: "u-bob", username: "bob", display_name: "Bob", role: "user", active: true };
const ANALYSTS = { id: "g-analysts", name: "Analysts", description: "Read only", member_ids: ["u-ana"] };
const ROLES = [
  { id: "builtin:reader", name: "reader", operations: ["SELECT", "EXPORT"], builtin: true, description: null },
  { id: "r-custom", name: "Loader", operations: ["SELECT", "INSERT"], builtin: false, description: null },
];
const GRANTS = [{ id: "g1", subject: { kind: "group", id: "g-analysts" }, scope: { kind: "all" }, effect: "allow", operations: null, role_id: "builtin:reader", expires_at: null, note: null }];

function manyGroups(count: number) {
  return Array.from({ length: count }, (_, index) => ({ id: `g-${index}`, name: `Group ${String(index).padStart(2, "0")}`, description: null, member_ids: [] }));
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function flush() {
  for (let i = 0; i < 16; i += 1) {
    await Promise.resolve();
    await nextTick();
  }
}

function byTestId<T extends Element = HTMLElement>(root: ParentNode, id: string): T {
  return root.querySelector<T>(`[data-testid="${id}"]`)!;
}

function setValue(element: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement, value: string) {
  element.value = value;
  element.dispatchEvent(new Event(element instanceof HTMLSelectElement ? "change" : "input"));
}

describe("admin groups and roles", () => {
  let requests: { path: string; body: any }[];
  let groups: unknown[];
  let routes: AdminRoute[];
  let mounted: App | null;

  function mount(component: Component, props: Record<string, unknown> = {}): HTMLElement {
    const root = document.createElement("div");
    document.body.append(root);
    const Wrapper = defineComponent({
      setup() {
        const directory = createAdminDirectory(ref("u-admin"));
        provide(ADMIN_DIRECTORY, directory);
        provide(ADMIN_CONFIRM, async () => true);
        provide(ADMIN_NAVIGATOR, { go: (route: AdminRoute) => routes.push(route) });
        void directory.refresh();
        return () => h(component, props);
      },
    });
    mounted = createApp(Wrapper);
    mounted.mount(root);
    return root;
  }

  beforeEach(() => {
    requests = [];
    routes = [];
    groups = [ANALYSTS];
    mounted = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input).split("/api/")[1];
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        requests.push({ path, body });
        if (path === "connection/list") return jsonResponse([]);
        if (path === "admin/users/list") return jsonResponse([ADMIN, ANA, BOB]);
        if (path === "admin/groups/list") return jsonResponse(groups);
        if (path === "admin/roles/list") return jsonResponse(ROLES);
        if (path === "admin/grants/list") return jsonResponse(GRANTS);
        if (path === "admin/groups/create") {
          const created = { id: "g-new", name: body.name, description: body.description, member_ids: [] };
          groups = [...groups, created];
          return jsonResponse(created, 201);
        }
        if (path === "admin/groups/set-members") {
          groups = (groups as { id: string }[]).map((group) => (group.id === body.id ? { ...group, member_ids: body.user_ids } : group));
          return jsonResponse({ ok: true });
        }
        if (path === "admin/roles/create") return jsonResponse({ id: "r-new", name: body.name, operations: body.operations, builtin: false, description: body.description }, 201);
        return jsonResponse({ ok: true });
      }),
    );
  });

  afterEach(() => {
    mounted?.unmount();
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("should list groups with members and permission counts", async () => {
    const root = mount(GroupsSection);
    await flush();
    const rows = root.querySelectorAll('[data-testid="admin-groups-table-row"]');
    expect(rows).toHaveLength(1);
    expect(rows[0]!.textContent).toContain("Analysts");
    expect(rows[0]!.textContent).toContain('adminConsole.groups.membersCount:{"count":1}');
    expect(rows[0]!.textContent).toContain('adminConsole.groups.permissionsCount:{"count":1}');
    (rows[0] as HTMLElement).click();
    expect(routes).toEqual([{ section: "group", id: "g-analysts" }]);
  });

  it("should paginate and search the group list", async () => {
    groups = manyGroups(25);
    const root = mount(GroupsSection);
    await flush();
    expect(root.querySelectorAll('[data-testid="admin-groups-table-row"]')).toHaveLength(20);
    byTestId(root, "admin-pagination-next").click();
    await flush();
    expect(root.querySelectorAll('[data-testid="admin-groups-table-row"]')).toHaveLength(5);
    setValue(byTestId<HTMLInputElement>(root, "admin-search"), "group 07");
    await flush();
    const rows = root.querySelectorAll('[data-testid="admin-groups-table-row"]');
    expect(rows).toHaveLength(1);
    expect(rows[0]!.textContent).toContain("Group 07");
  });

  it("should create a group from the dialog", async () => {
    const root = mount(GroupsSection);
    await flush();
    byTestId(root, "admin-groups-new").click();
    await flush();
    setValue(byTestId<HTMLInputElement>(document.body, "group-form-name"), "Loaders");
    setValue(byTestId<HTMLTextAreaElement>(document.body, "group-form-description"), "Nightly loads");
    await flush();
    byTestId<HTMLButtonElement>(document.body, "group-form-submit").click();
    await flush();
    expect(requests.find((request) => request.path === "admin/groups/create")?.body).toEqual({ name: "Loaders", description: "Nightly loads" });
    expect(routes).toEqual([{ section: "group", id: "g-new" }]);
  });

  it("should add members through the picker", async () => {
    const root = mount(GroupDetailPage, { groupId: "g-analysts" });
    await flush();
    expect(root.querySelectorAll('[data-testid="admin-group-members-row"]')).toHaveLength(1);
    byTestId(root, "admin-group-add-members").click();
    await flush();
    const options = document.body.querySelectorAll<HTMLLabelElement>('[data-testid="member-picker-option"]');
    expect(options).toHaveLength(2);
    const bob = [...options].find((option) => option.textContent?.includes("bob"))!;
    const box = bob.querySelector<HTMLInputElement>('input[type="checkbox"]')!;
    box.checked = true;
    box.dispatchEvent(new Event("change"));
    await flush();
    byTestId<HTMLButtonElement>(document.body, "member-picker-submit").click();
    await flush();
    expect(requests.find((request) => request.path === "admin/groups/set-members")?.body).toEqual({ id: "g-analysts", user_ids: ["u-ana", "u-bob"] });
    expect(root.querySelectorAll('[data-testid="admin-group-members-row"]')).toHaveLength(2);
  });

  it("should create a role with the selected operations", async () => {
    const root = mount(RolesSection);
    await flush();
    byTestId(root, "admin-roles-new").click();
    await flush();
    setValue(byTestId<HTMLInputElement>(document.body, "role-form-name"), "Writer");
    byTestId(document.body, "role-form-all-write").click();
    await flush();
    byTestId<HTMLButtonElement>(document.body, "role-form-submit").click();
    await flush();
    expect(requests.find((request) => request.path === "admin/roles/create")?.body).toEqual({ name: "Writer", operations: ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "IMPORT"], description: null });
  });

  it("should only offer duplicating built-in roles", async () => {
    const root = mount(RolesSection);
    await flush();
    const rows = root.querySelectorAll<HTMLElement>('[data-testid="admin-roles-table-row"]');
    expect(rows).toHaveLength(2);
    const builtinRow = [...rows].find((row) => row.textContent?.includes("access.builtinRoles.reader"))!;
    expect(builtinRow.textContent).toContain('adminConsole.roles.usageCount:{"count":1}');
    const trigger = builtinRow.querySelector<HTMLButtonElement>('[data-testid="admin-row-menu"]')!;
    trigger.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await flush();
    expect(byTestId(document.body, "admin-action-duplicate")).not.toBeNull();
    expect(document.body.querySelector('[data-testid="admin-action-delete"]')).toBeNull();
    expect(document.body.querySelector('[data-testid="admin-action-edit"]')).toBeNull();
  });
});
