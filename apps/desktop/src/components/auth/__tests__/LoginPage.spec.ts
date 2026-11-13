// @vitest-environment happy-dom

import { createApp, nextTick, type App } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("vue-i18n", () => ({ useI18n: () => ({ t: (key: string) => key }) }));
// The logo reads the settings store; the login form does not, so stub it rather
// than booting pinia for a component that renders nothing here.
vi.mock("@/components/icons/AppLogo.vue", () => ({ default: { name: "AppLogo", render: () => null } }));

import LoginPage from "../LoginPage.vue";

const CAPTCHA_BODY = { id: "challenge-1", image: "data:image/png;base64,AAAA", expires_in: 300 };

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function mount(props: Record<string, unknown> = {}): { root: HTMLElement; app: App } {
  const root = document.createElement("div");
  document.body.append(root);
  const app = createApp(LoginPage, props);
  app.mount(root);
  return { root, app };
}

// fetch + Response.json both resolve on later microtasks than nextTick, so
// drain a few turns before asserting on the rendered result.
async function flush() {
  for (let i = 0; i < 12; i += 1) {
    await Promise.resolve();
    await nextTick();
  }
}

function typeInto(input: HTMLInputElement, value: string) {
  input.value = value;
  input.dispatchEvent(new Event("input"));
}

describe("LoginPage captcha", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/auth/captcha")) return jsonResponse(CAPTCHA_BODY);
      return jsonResponse({ ok: true });
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("loads a challenge on mount and renders its image", async () => {
    const { root, app } = mount();
    await flush();

    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("/api/auth/captcha"), expect.anything());
    const image = root.querySelector<HTMLImageElement>('[data-testid="captcha-image"]');
    expect(image?.getAttribute("src")).toBe(CAPTCHA_BODY.image);
    app.unmount();
  });

  it("sends the challenge id and the typed code with the password", async () => {
    const { root, app } = mount();
    await flush();

    typeInto(root.querySelector<HTMLInputElement>('[data-testid="captcha-input"]')!, "abcde");
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="username-input"]')!, " ana ");
    const passwordInput = root.querySelector<HTMLInputElement>('input[type="password"]')!;
    typeInto(passwordInput, "secret");
    await nextTick();

    root.querySelector("form")!.dispatchEvent(new Event("submit"));
    await flush();

    const loginCall = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/api/auth/login"));
    expect(loginCall).toBeTruthy();
    const body = JSON.parse(String((loginCall![1] as RequestInit).body));
    expect(body).toEqual({ username: "ana", password: "secret", captcha_id: "challenge-1", captcha_code: "abcde" });
    app.unmount();
  });

  it("refreshes the challenge after a rejected attempt", async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/auth/captcha")) return jsonResponse({ ...CAPTCHA_BODY, id: `challenge-${fetchMock.mock.calls.length}` });
      return jsonResponse({ error: "captcha_invalid" }, 400);
    });
    const { root, app } = mount();
    await flush();

    typeInto(root.querySelector<HTMLInputElement>('[data-testid="captcha-input"]')!, "zzzzz");
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="username-input"]')!, "admin");
    typeInto(root.querySelector<HTMLInputElement>('input[type="password"]')!, "secret");
    await nextTick();
    root.querySelector("form")!.dispatchEvent(new Event("submit"));
    await flush();

    const captchaCalls = fetchMock.mock.calls.filter(([url]) => String(url).includes("/api/auth/captcha"));
    expect(captchaCalls.length).toBeGreaterThanOrEqual(2);
    // The consumed challenge is replaced and the input cleared.
    expect(root.querySelector<HTMLInputElement>('[data-testid="captcha-input"]')!.value).toBe("");
    app.unmount();
  });

  it("hides the challenge when the server answers 204 and logs in without one", async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/auth/captcha")) return new Response(null, { status: 204 });
      return jsonResponse({ ok: true });
    });
    const { root, app } = mount();
    await flush();

    expect(root.querySelector('[data-testid="captcha-input"]')).toBeNull();
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="username-input"]')!, "admin");
    typeInto(root.querySelector<HTMLInputElement>('input[type="password"]')!, "secret");
    await nextTick();
    // Without a challenge on screen the submit button must not wait for one.
    expect(root.querySelector<HTMLButtonElement>('button[type="submit"]')!.disabled).toBe(false);
    root.querySelector("form")!.dispatchEvent(new Event("submit"));
    await flush();

    const loginCall = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/api/auth/login"));
    expect(loginCall, JSON.stringify(fetchMock.mock.calls.map(([url]) => String(url)))).toBeTruthy();
    expect(JSON.parse(String((loginCall![1] as RequestInit).body))).toEqual({ username: "admin", password: "secret" });
    app.unmount();
  });

  it("reveals the challenge after a failed attempt when the mode is auto", async () => {
    let attempts = 0;
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/auth/captcha")) {
        // auto: no challenge until the first failure
        return attempts === 0 ? new Response(null, { status: 204 }) : jsonResponse(CAPTCHA_BODY);
      }
      attempts += 1;
      return jsonResponse({ error: "invalid_credentials" }, 401);
    });
    const { root, app } = mount();
    await flush();
    expect(root.querySelector('[data-testid="captcha-input"]')).toBeNull();

    typeInto(root.querySelector<HTMLInputElement>('[data-testid="username-input"]')!, "ana");
    typeInto(root.querySelector<HTMLInputElement>('input[type="password"]')!, "wrong");
    await nextTick();
    root.querySelector("form")!.dispatchEvent(new Event("submit"));
    await flush();

    expect(root.querySelector('[data-testid="captcha-input"]')).not.toBeNull();
    expect(root.querySelector('[data-testid="captcha-image"]')?.getAttribute("src")).toBe(CAPTCHA_BODY.image);
    const refreshed = fetchMock.mock.calls.map(([url]) => String(url)).filter((url) => url.includes("/api/auth/captcha"));
    expect(refreshed.at(-1)).toContain("?username=ana");
    app.unmount();
  });

  it("keeps the submit button disabled until a username is typed", async () => {
    fetchMock.mockImplementation(async () => new Response(null, { status: 204 }));
    const { root, app } = mount();
    await flush();
    typeInto(root.querySelector<HTMLInputElement>('input[type="password"]')!, "secret");
    await nextTick();
    expect(root.querySelector<HTMLButtonElement>('button[type="submit"]')!.disabled).toBe(true);
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="username-input"]')!, "admin");
    await nextTick();
    expect(root.querySelector<HTMLButtonElement>('button[type="submit"]')!.disabled).toBe(false);
    app.unmount();
  });

  it("reports when the server requires a password change after login", async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      if (String(input).includes("/api/auth/captcha")) return new Response(null, { status: 204 });
      return jsonResponse({ ok: true, must_change_password: true });
    });
    const authenticated = vi.fn();
    const { root, app } = mount({ onAuthenticated: authenticated });
    await flush();
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="username-input"]')!, "ana");
    typeInto(root.querySelector<HTMLInputElement>('input[type="password"]')!, "secret");
    await nextTick();
    root.querySelector("form")!.dispatchEvent(new Event("submit"));
    await flush();
    expect(authenticated).toHaveBeenCalledWith({ mustChangePassword: true, mfaSetupRequired: false });
    app.unmount();
  });

  it("should ask for the second factor before finishing the sign-in", async () => {
    const requests: { url: string; body: any }[] = [];
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/api/auth/captcha")) return new Response(null, { status: 204 });
      requests.push({ url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (url.includes("/api/auth/login")) return jsonResponse({ ok: false, mfa_required: true, challenge: "challenge-token" });
      if (requests.filter((request) => request.url.includes("/api/auth/mfa/verify")).length === 1) return jsonResponse({ error: "mfa_code_invalid" }, 401);
      return jsonResponse({ ok: true, must_change_password: false, mfa_setup_required: false });
    });
    const authenticated = vi.fn();
    const { root, app } = mount({ onAuthenticated: authenticated });
    await flush();
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="username-input"]')!, "ana");
    typeInto(root.querySelector<HTMLInputElement>('input[type="password"]')!, "secret");
    await nextTick();
    root.querySelector("form")!.dispatchEvent(new Event("submit"));
    await flush();
    expect(authenticated).not.toHaveBeenCalled();
    const form = root.querySelector<HTMLFormElement>('[data-testid="mfa-login-form"]')!;
    expect(form).not.toBeNull();

    typeInto(root.querySelector<HTMLInputElement>('[data-testid="mfa-login-code"]')!, "000000");
    await nextTick();
    form.dispatchEvent(new Event("submit"));
    await flush();
    expect(root.textContent).toContain("mfa.errors.codeInvalid");
    expect(authenticated).not.toHaveBeenCalled();

    typeInto(root.querySelector<HTMLInputElement>('[data-testid="mfa-login-code"]')!, "123 456");
    await nextTick();
    root.querySelector<HTMLFormElement>('[data-testid="mfa-login-form"]')!.dispatchEvent(new Event("submit"));
    await flush();
    expect(requests.at(-1)).toEqual({ url: expect.stringContaining("/api/auth/mfa/verify"), body: { challenge: "challenge-token", code: "123 456" } });
    expect(authenticated).toHaveBeenCalledWith({ mustChangePassword: false, mfaSetupRequired: false });
    app.unmount();
  });

  it("sends the setup token and the administrator name while setting up", async () => {
    const { root, app } = mount({ setupMode: true });
    await flush();
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="setup-token-input"]')!, " token-123 ");
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="username-input"]')!, "boss");
    const [password, confirm] = Array.from(root.querySelectorAll<HTMLInputElement>('input[type="password"]'));
    typeInto(password, "boss-password");
    typeInto(confirm, "boss-password");
    await nextTick();
    root.querySelector("form")!.dispatchEvent(new Event("submit"));
    await flush();
    const setupCall = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/api/auth/setup"));
    expect(JSON.parse(String((setupCall![1] as RequestInit).body))).toEqual({ setup_token: "token-123", username: "boss", password: "boss-password" });
    app.unmount();
  });

  it("does not request a challenge while setting up the first password", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    const app = createApp(LoginPage, { setupMode: true });
    app.mount(root);
    await flush();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(root.querySelector('[data-testid="captcha-input"]')).toBeNull();
    app.unmount();
  });
});
