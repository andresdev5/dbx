// @vitest-environment happy-dom

import { createApp, defineComponent, h, nextTick, provide, ref, type App, type Component } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string, values?: Record<string, unknown>) => (values ? `${key}:${JSON.stringify(values)}` : key), locale: ref("en") }),
}));

import { ADMIN_CONFIRM } from "@/lib/auth/adminConfirm";
import { ADMIN_DIRECTORY, createAdminDirectory } from "@/lib/auth/adminDirectory";
import { ADMIN_NAVIGATOR, type AdminRoute } from "@/lib/auth/adminNavigation";
import UsersSection from "../users/UsersSection.vue";
import UserDetailPage from "../users/UserDetailPage.vue";

const ADMIN = { id: "u-admin", username: "admin", display_name: null, role: "admin", active: true, must_change_password: false, mfa_enabled: false, mfa_required: false, last_login_at: 1, created_at: 1 };
const ANA = { id: "u-ana", username: "ana", display_name: "Ana", role: "user", active: true, must_change_password: true, mfa_enabled: true, mfa_required: false, last_login_at: null, created_at: 2 };
const ANALYSTS = { id: "g-analysts", name: "Analysts", description: null, member_ids: [] as string[] };

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function flush() {
  for (let i = 0; i < 16; i += 1) {
    await Promise.resolve();
    await nextTick();
  }
}

function byTestId<T extends Element = HTMLElement>(root: ParentNode, id: string): T | null {
  return root.querySelector<T>(`[data-testid="${id}"]`);
}

function typeInto(input: HTMLInputElement, value: string) {
  input.value = value;
  input.dispatchEvent(new Event("input"));
}

describe("admin console users", () => {
  let requests: { path: string; body: any }[];
  let users: (typeof ADMIN | typeof ANA)[];
  let confirmAnswer: boolean;
  let routes: AdminRoute[];
  let mounted: App | null;

  function mount(component: Component, props: Record<string, unknown> = {}): HTMLElement {
    const root = document.createElement("div");
    document.body.append(root);
    const Wrapper = defineComponent({
      setup() {
        const directory = createAdminDirectory(ref(ADMIN.id));
        provide(ADMIN_DIRECTORY, directory);
        provide(ADMIN_CONFIRM, async () => confirmAnswer);
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
    users = [ADMIN, ANA];
    confirmAnswer = true;
    routes = [];
    mounted = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input).split("/api/")[1];
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        requests.push({ path, body });
        if (path === "admin/users/list") return jsonResponse(users);
        if (path === "admin/groups/list") return jsonResponse([ANALYSTS]);
        if (path === "admin/roles/list") return jsonResponse([]);
        if (path === "admin/grants/list") return jsonResponse([]);
        if (path === "connection/list") return jsonResponse([]);
        if (path === "admin/users/create") {
          if (body.username === "taken") return jsonResponse({ error: "username_taken" }, 409);
          return jsonResponse({ user: { ...ANA, id: "u-bob", username: body.username, display_name: null }, temporary_password: "Temp-Pass-123" }, 201);
        }
        if (path === "admin/users/set-active") return jsonResponse({ ...ANA, active: body.active });
        if (path === "admin/users/set-mfa-required") return jsonResponse({ ...ANA, mfa_required: body.required });
        if (path === "admin/users/reset-mfa") return jsonResponse({ ...ANA, mfa_enabled: false });
        if (path === "admin/users/reset-password") return jsonResponse({ user: { ...ANA, must_change_password: true }, temporary_password: "Reset-Pass-456" });
        return jsonResponse({ ok: true });
      }),
    );
  });

  afterEach(() => {
    mounted?.unmount();
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("should list users with their role, status and two-step badges", async () => {
    const root = mount(UsersSection);
    await flush();
    const rows = root.querySelectorAll('[data-testid="admin-users-table-row"]');
    expect(rows).toHaveLength(2);
    expect(rows[0]!.textContent).toContain("admin");
    expect(rows[0]!.textContent).toContain("adminConsole.you");
    expect(rows[1]!.textContent).toContain("Ana");
    expect(rows[1]!.textContent).toContain("adminConsole.users.status.mustChange");
    expect(byTestId(rows[1]!, "mfa-badge")!.textContent).toContain("adminConsole.users.mfa.enabled");
  });

  it("should filter by search text and status", async () => {
    users = [ADMIN, ANA, { ...ANA, id: "u-old", username: "old", display_name: null, active: false }];
    const root = mount(UsersSection);
    await flush();
    typeInto(byTestId<HTMLInputElement>(root, "admin-search")!, "an");
    await flush();
    expect(root.querySelectorAll('[data-testid="admin-users-table-row"]')).toHaveLength(1);

    typeInto(byTestId<HTMLInputElement>(root, "admin-search")!, "");
    const status = byTestId<HTMLSelectElement>(root, "admin-users-status-filter")!;
    status.value = "disabled";
    status.dispatchEvent(new Event("change"));
    await flush();
    const rows = root.querySelectorAll('[data-testid="admin-users-table-row"]');
    expect(rows).toHaveLength(1);
    expect(rows[0]!.textContent).toContain("old");
  });

  it("should paginate long user lists", async () => {
    users = Array.from({ length: 45 }, (_, index) => ({ ...ANA, id: `u-${index}`, username: `user${String(index).padStart(2, "0")}`, display_name: null }));
    const root = mount(UsersSection);
    await flush();
    expect(root.querySelectorAll('[data-testid="admin-users-table-row"]')).toHaveLength(20);
    expect(byTestId(root, "admin-pagination-range")!.textContent).toContain('"total":45');
    byTestId<HTMLButtonElement>(root, "admin-pagination-page-3")!.click();
    await flush();
    expect(root.querySelectorAll('[data-testid="admin-users-table-row"]')).toHaveLength(5);
  });

  it("should create a user from the dialog and show the temporary password once", async () => {
    const root = mount(UsersSection);
    await flush();
    byTestId<HTMLButtonElement>(root, "admin-users-new")!.click();
    await flush();
    typeInto(byTestId<HTMLInputElement>(document.body, "user-form-username")!, " bob ");
    await flush();
    byTestId<HTMLButtonElement>(document.body, "user-form-submit")!.click();
    await flush();
    expect(requests.find((request) => request.path === "admin/users/create")?.body).toEqual({ username: "bob", display_name: null, role: "user", password: null });
    expect(byTestId(document.body, "issued-password-value")?.textContent).toBe("Temp-Pass-123");
    expect(root.querySelectorAll('[data-testid="admin-users-table-row"]')).toHaveLength(3);
  });

  it("should translate server errors in the create dialog", async () => {
    const root = mount(UsersSection);
    await flush();
    byTestId<HTMLButtonElement>(root, "admin-users-new")!.click();
    await flush();
    typeInto(byTestId<HTMLInputElement>(document.body, "user-form-username")!, "taken");
    await flush();
    byTestId<HTMLButtonElement>(document.body, "user-form-submit")!.click();
    await flush();
    expect(byTestId(document.body, "user-form-error")?.textContent).toBe("auth.usernameTaken");
  });

  it("should open the user page when a row is clicked", async () => {
    const root = mount(UsersSection);
    await flush();
    root.querySelectorAll<HTMLElement>('[data-testid="admin-users-table-row"]')[1]!.click();
    expect(routes).toEqual([{ section: "user", id: "u-ana" }]);
  });

  it("should offer no account actions on the current administrator", async () => {
    const root = mount(UserDetailPage, { userId: ADMIN.id });
    await flush();
    expect(byTestId(root, "admin-user-edit")).not.toBeNull();
    expect(byTestId(root, "admin-user-delete")).toBeNull();
    expect(byTestId(root, "admin-user-toggle-active")).toBeNull();
    expect(byTestId(root, "admin-user-reset-password")).toBeNull();
  });

  it("should disable another user only after confirmation", async () => {
    const root = mount(UserDetailPage, { userId: ANA.id });
    await flush();
    confirmAnswer = false;
    byTestId<HTMLButtonElement>(root, "admin-user-toggle-active")!.click();
    await flush();
    expect(requests.some((request) => request.path === "admin/users/set-active")).toBe(false);

    confirmAnswer = true;
    byTestId<HTMLButtonElement>(root, "admin-user-toggle-active")!.click();
    await flush();
    expect(requests.find((request) => request.path === "admin/users/set-active")?.body).toEqual({ id: ANA.id, active: false });
    expect(root.textContent).toContain("adminConsole.users.status.disabled");
  });

  it("should reset the password and two-step sign-in of another user", async () => {
    const root = mount(UserDetailPage, { userId: ANA.id });
    await flush();
    byTestId<HTMLButtonElement>(root, "admin-user-reset-password")!.click();
    await flush();
    expect(requests.find((request) => request.path === "admin/users/reset-password")?.body).toEqual({ id: ANA.id });
    expect(byTestId(document.body, "issued-password-value")?.textContent).toBe("Reset-Pass-456");

    byTestId<HTMLButtonElement>(root, "admin-user-reset-mfa")!.click();
    await flush();
    expect(requests.find((request) => request.path === "admin/users/reset-mfa")?.body).toEqual({ id: ANA.id });
    expect(byTestId(root, "admin-user-reset-mfa")).toBeNull();
  });

  it("should add the user to a group from the groups tab", async () => {
    const root = mount(UserDetailPage, { userId: ANA.id });
    await flush();
    byTestId<HTMLButtonElement>(root, "admin-tab-groups")!.click();
    await flush();
    const group = byTestId(root, "admin-user-group")!;
    group.querySelector<HTMLButtonElement>('[data-slot="switch"], button[role="switch"]')!.click();
    await flush();
    expect(requests.find((request) => request.path === "admin/groups/set-members")?.body).toEqual({ id: "g-analysts", user_ids: ["u-ana"] });
  });
});
