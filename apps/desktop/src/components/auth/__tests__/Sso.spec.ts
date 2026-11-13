// @vitest-environment happy-dom

import { createApp, nextTick, ref, type App, type Component } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string, values?: Record<string, unknown>) => (values ? `${key}:${JSON.stringify(values)}` : key), locale: ref("en") }),
}));
vi.mock("@/components/icons/AppLogo.vue", () => ({ default: { name: "AppLogo", render: () => null } }));

import LoginPage from "../LoginPage.vue";

const PROVIDERS = [
  { id: "kc", name: "Keycloak", kind: "oidc" },
  { id: "corp", name: "Corporate LDAP", kind: "ldap" },
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

function setValue(element: HTMLInputElement | HTMLSelectElement, value: string) {
  element.value = value;
  element.dispatchEvent(new Event(element instanceof HTMLSelectElement ? "change" : "input"));
}

describe("single sign-on", () => {
  let requests: { url: string; body: any }[];

  beforeEach(() => {
    requests = [];
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
    window.history.replaceState(null, "", "/");
  });

  it("should offer identity providers and send the chosen directory with the password", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        requests.push({ url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
        if (url.includes("/api/auth/captcha")) return new Response(null, { status: 204 });
        if (url.includes("/api/auth/providers")) return jsonResponse(PROVIDERS);
        return jsonResponse({ ok: true });
      }),
    );
    window.history.replaceState(null, "", "/login?sso_error=sso_user_disabled");
    const assign = vi.fn();
    vi.spyOn(window.location, "assign").mockImplementation(assign);
    const { root, app } = mount(LoginPage);
    await flush();
    expect(root.textContent).toContain("sso.errors.sso_user_disabled");
    expect(window.location.search).toBe("");

    const button = byTestId<HTMLButtonElement>(root, "sso-kc");
    expect(button.textContent).toContain('sso.continueWith:{"name":"Keycloak"}');
    button.click();
    expect(assign).toHaveBeenCalledWith(expect.stringContaining("/api/auth/oidc/kc/start"));

    setValue(byTestId<HTMLSelectElement>(root, "login-source"), "corp");
    setValue(byTestId<HTMLInputElement>(root, "username-input"), "ana");
    setValue(root.querySelector<HTMLInputElement>('input[type="password"]')!, "secret");
    await nextTick();
    root.querySelector("form")!.dispatchEvent(new Event("submit"));
    await flush();
    expect(requests.find((request) => request.url.includes("/api/auth/login"))?.body).toEqual({ username: "ana", password: "secret", provider: "corp" });
    app.unmount();
  });
});
