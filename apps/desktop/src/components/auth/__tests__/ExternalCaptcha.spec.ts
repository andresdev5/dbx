// @vitest-environment happy-dom

import { createApp, nextTick, ref, type App, type Component } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("vue-i18n", () => ({ useI18n: () => ({ t: (key: string) => key, locale: ref("en") }) }));
vi.mock("@/components/icons/AppLogo.vue", () => ({ default: { name: "AppLogo", render: () => null } }));

import LoginPage from "../LoginPage.vue";
import CaptchaProviderSetting from "../captcha/CaptchaProviderSetting.vue";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function flush() {
  for (let i = 0; i < 20; i += 1) {
    await Promise.resolve();
    await nextTick();
  }
}

function mount(component: Component, props: Record<string, unknown> = {}): { root: HTMLElement; app: App } {
  const root = document.createElement("div");
  document.body.append(root);
  const app = createApp(component, props);
  app.mount(root);
  return { root, app };
}

function typeInto(input: HTMLInputElement, value: string) {
  input.value = value;
  input.dispatchEvent(new Event("input"));
}

describe("external captcha providers", () => {
  let requests: { url: string; body: any }[];
  let renders: number;

  beforeEach(() => {
    requests = [];
    renders = 0;
    vi.stubGlobal("turnstile", {
      render: (_container: HTMLElement, options: { sitekey: string; callback: (token: string) => void }) => {
        renders += 1;
        options.callback(`token-${renders}-${options.sitekey}`);
        return `widget-${renders}`;
      },
      reset: vi.fn(),
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("should send the provider token and fall back to the built-in image when the provider is down", async () => {
    let providerDown = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        requests.push({ url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
        if (url.includes("/api/auth/captcha")) {
          return providerDown ? jsonResponse({ provider: "builtin", id: "c-1", image: "data:image/png;base64,AAAA", expires_in: 300 }) : jsonResponse({ provider: "turnstile", site_key: "site-k" });
        }
        if (url.includes("/api/auth/login")) {
          providerDown = true;
          return jsonResponse({ error: "captcha_provider_unavailable" }, 503);
        }
        return jsonResponse({ ok: true });
      }),
    );
    const { root, app } = mount(LoginPage);
    await flush();
    expect(root.querySelector('[data-testid="external-captcha"]')).not.toBeNull();
    expect(root.querySelector('[data-testid="captcha-image"]')).toBeNull();
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="username-input"]')!, "ana");
    typeInto(root.querySelector<HTMLInputElement>('input[type="password"]')!, "secret");
    await nextTick();
    expect(root.querySelector<HTMLButtonElement>('button[type="submit"]')!.disabled).toBe(false);
    root.querySelector("form")!.dispatchEvent(new Event("submit"));
    await flush();
    const login = requests.find((request) => request.url.includes("/api/auth/login"))!;
    expect(login.body).toEqual({ username: "ana", password: "secret", captcha_token: "token-1-site-k" });
    expect(root.textContent).toContain("captchaProvider.errors.unavailable");
    expect(root.querySelector('[data-testid="external-captcha"]')).toBeNull();
    expect(root.querySelector('[data-testid="captcha-image"]')).not.toBeNull();
    app.unmount();
  });

  it("should save provider settings without echoing or resending a kept secret", async () => {
    let saved: any;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        if (url.endsWith("/captcha")) return jsonResponse({ provider: "turnstile", site_key: "old", endpoint: "", has_secret: true, provider_env_locked: false, fallback_active: false });
        saved = body;
        return jsonResponse({ provider: body.provider, site_key: body.site_key, endpoint: body.endpoint, has_secret: true, provider_env_locked: false, fallback_active: false });
      }),
    );
    const { root, app } = mount(CaptchaProviderSetting);
    await flush();
    const secret = root.querySelector<HTMLInputElement>('[data-testid="captcha-provider-secret"]')!;
    expect(secret.placeholder).toBe("captchaProvider.secretKept");
    const select = root.querySelector<HTMLSelectElement>('[data-testid="captcha-provider-select"]')!;
    select.value = "cap";
    select.dispatchEvent(new Event("change"));
    await flush();
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="captcha-provider-endpoint"]')!, "https://cap.example.com");
    typeInto(root.querySelector<HTMLInputElement>('[data-testid="captcha-provider-site-key"]')!, "site-1");
    await nextTick();
    root.querySelector<HTMLFormElement>('[data-testid="captcha-provider"]')!.dispatchEvent(new Event("submit"));
    await flush();
    expect(saved).toEqual({ provider: "cap", site_key: "site-1", endpoint: "https://cap.example.com" });
    expect(root.querySelector('[data-testid="captcha-provider-message"]')!.textContent).toContain("captchaProvider.saved");
    app.unmount();
  });
});
