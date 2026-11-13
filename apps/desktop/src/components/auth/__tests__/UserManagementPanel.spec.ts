// @vitest-environment happy-dom

import { createApp, nextTick, ref, type App } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string, values?: Record<string, unknown>) => (values ? `${key}:${JSON.stringify(values)}` : key), locale: ref("en") }),
}));

import UserManagementPanel from "../UserManagementPanel.vue";

const ADMIN = { id: "u-admin", username: "admin", display_name: null, role: "admin", active: true, must_change_password: false, last_login_at: 1, created_at: 1 };
const ANA = { id: "u-ana", username: "ana", display_name: "Ana", role: "user", active: true, must_change_password: true, last_login_at: null, created_at: 2 };

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function flush() {
  for (let i = 0; i < 12; i += 1) {
    await Promise.resolve();
    await nextTick();
  }
}

function mount(): { root: HTMLElement; app: App } {
  const root = document.createElement("div");
  document.body.append(root);
  const app = createApp(UserManagementPanel, { currentUserId: ADMIN.id });
  app.mount(root);
  return { root, app };
}

function typeInto(input: HTMLInputElement, value: string) {
  input.value = value;
  input.dispatchEvent(new Event("input"));
}

describe("UserManagementPanel", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let requests: { path: string; body: any }[];

  beforeEach(() => {
    requests = [];
    fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input).split("/api/admin/users/")[1];
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      requests.push({ path, body });
      if (path === "list") return jsonResponse([ADMIN, ANA]);
      if (path === "create") {
        if (body.username === "taken") return jsonResponse({ error: "username_taken" }, 409);
        return jsonResponse({ user: { ...ANA, id: "u-bob", username: body.username, display_name: null }, temporary_password: "Temp-Pass-123" }, 201);
      }
      if (path === "set-active") return jsonResponse({ ...ANA, active: body.active });
      if (path === "mfa-policy") return jsonResponse({ required_all: false });
      if (path === "mfa-policy/save") return jsonResponse({ required_all: body.required_all });
      if (path === "set-mfa-required") return jsonResponse({ ...ANA, mfa_enabled: true, mfa_required: body.required });
      if (path === "reset-mfa") return jsonResponse({ ...ANA, mfa_enabled: false });
      return jsonResponse({ ok: true });
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("lists users and offers no destructive actions on the current account", async () => {
    const { root, app } = mount();
    await flush();
    const rows = root.querySelectorAll('[data-testid="managed-user"]');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain("users.you");
    expect(rows[0].querySelectorAll("button")).toHaveLength(0);
    expect(rows[0].querySelector<HTMLSelectElement>("select")!.disabled).toBe(true);
    expect(rows[1].textContent).toContain("Ana");
    expect(rows[1].textContent).toContain("users.mustChange");
    expect(rows[1].querySelectorAll("button")).toHaveLength(4);
    expect(rows[0].querySelector('[data-testid="mfa-badge"]')!.textContent).toContain("mfa.badgeOff");
    app.unmount();
  });

  it("creates a user and shows the temporary password once", async () => {
    const { root, app } = mount();
    await flush();
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="new-user-username"]')!, " bob ");
    await nextTick();
    root.querySelector<HTMLFormElement>('[data-testid="create-user-form"]')!.dispatchEvent(new Event("submit"));
    await flush();
    expect(requests.find((request) => request.path === "create")?.body).toEqual({ username: "bob", display_name: null, role: "user", password: null });
    expect(root.querySelector('[data-testid="issued-password"]')?.textContent).toContain("Temp-Pass-123");
    expect(root.querySelectorAll('[data-testid="managed-user"]')).toHaveLength(3);
    app.unmount();
  });

  it("translates server errors", async () => {
    const { root, app } = mount();
    await flush();
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="new-user-username"]')!, "taken");
    await nextTick();
    root.querySelector<HTMLFormElement>('[data-testid="create-user-form"]')!.dispatchEvent(new Event("submit"));
    await flush();
    expect(root.querySelector('[data-testid="user-management-error"]')?.textContent).toBe("auth.usernameTaken");
    app.unmount();
  });

  it("disables another user", async () => {
    const { root, app } = mount();
    await flush();
    const anaRow = root.querySelectorAll('[data-testid="managed-user"]')[1];
    anaRow.querySelector<HTMLButtonElement>("button")!.click();
    await flush();
    expect(requests.find((request) => request.path === "set-active")?.body).toEqual({ id: ANA.id, active: false });
    expect(root.querySelectorAll('[data-testid="managed-user"]')[1].textContent).toContain("users.disabled");
    app.unmount();
  });

  it("should show two-factor status and manage the requirement", async () => {
    vi.stubGlobal("confirm", () => true);
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input).split("/api/admin/users/")[1];
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      requests.push({ path, body });
      if (path === "list") return jsonResponse([ADMIN, { ...ANA, mfa_enabled: true, mfa_required: false }]);
      if (path === "mfa-policy") return jsonResponse({ required_all: false });
      if (path === "mfa-policy/save") return jsonResponse({ required_all: body.required_all });
      if (path === "set-mfa-required") return jsonResponse({ ...ANA, mfa_enabled: true, mfa_required: body.required });
      if (path === "reset-mfa") return jsonResponse({ ...ANA, mfa_enabled: false, mfa_required: true });
      return jsonResponse({ ok: true });
    });
    const { root, app } = mount();
    await flush();
    const ana = () => root.querySelectorAll('[data-testid="managed-user"]')[1];
    expect(ana().querySelector('[data-testid="mfa-badge"]')!.textContent).toContain("mfa.badgeOn");

    ana().querySelector<HTMLButtonElement>('[data-testid="mfa-toggle-required"]')!.click();
    await flush();
    expect(requests.find((request) => request.path === "set-mfa-required")?.body).toEqual({ id: "u-ana", required: true });
    expect(ana().textContent).toContain("mfa.requiredShort");

    ana().querySelector<HTMLButtonElement>('[data-testid="mfa-reset"]')!.click();
    await flush();
    expect(requests.find((request) => request.path === "reset-mfa")?.body).toEqual({ id: "u-ana" });
    expect(ana().querySelector('[data-testid="mfa-badge"]')!.textContent).toContain("mfa.badgeOff");
    expect(ana().querySelector('[data-testid="mfa-reset"]')).toBeNull();

    const requireAll = root.querySelector<HTMLInputElement>('[data-testid="mfa-required-all"]')!;
    requireAll.checked = true;
    requireAll.dispatchEvent(new Event("change"));
    await flush();
    expect(requests.find((request) => request.path === "mfa-policy/save")?.body).toEqual({ required_all: true });
    app.unmount();
  });
});
