// @vitest-environment happy-dom

import { createApp, nextTick, ref, type App, type Component } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("vue-i18n", () => ({
  useI18n: () => ({ t: (key: string, values?: Record<string, unknown>) => (values ? `${key}:${JSON.stringify(values)}` : key), locale: ref("en") }),
}));
vi.mock("@/components/icons/AppLogo.vue", () => ({ default: { name: "AppLogo", render: () => null } }));

import MfaSetup from "../mfa/MfaSetup.vue";
import MfaAccountCard from "../mfa/MfaAccountCard.vue";
import { dismissMfaRecommendation, mfaRecommendationDismissed } from "@/lib/auth/mfaRecommendation";

const URI = "otpauth://totp/DBX:ana?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=DBX&algorithm=SHA1&digits=6&period=30";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function flush() {
  for (let i = 0; i < 16; i += 1) {
    await Promise.resolve();
    await nextTick();
  }
}

function mount(component: Component, props: Record<string, unknown>): { root: HTMLElement; app: App } {
  const root = document.createElement("div");
  document.body.append(root);
  const app = createApp(component, props);
  app.mount(root);
  return { root, app };
}

function byTestId<T extends Element = HTMLElement>(root: ParentNode, id: string): T {
  return root.querySelector<T>(`[data-testid="${id}"]`)!;
}

function typeInto(input: HTMLInputElement, value: string) {
  input.value = value;
  input.dispatchEvent(new Event("input"));
}

describe("two-factor components", () => {
  let requests: { path: string; body: any }[];
  let status: Record<string, unknown>;

  beforeEach(() => {
    requests = [];
    status = { enabled: false, required: false, setup_required: false, recovery_codes_left: 0 };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input).split("/api/")[1];
        const body = init?.body ? JSON.parse(String(init.body)) : undefined;
        requests.push({ path, body });
        if (path === "auth/mfa/setup") return jsonResponse({ secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", otpauth_uri: URI });
        if (path === "auth/mfa/confirm") {
          if (body.code === "000000") return jsonResponse({ error: "mfa_code_invalid" }, 400);
          return jsonResponse({ recovery_codes: ["aaaaa-bbbbb", "ccccc-ddddd"] });
        }
        if (path === "auth/mfa/status") return jsonResponse(status);
        if (path === "auth/mfa/disable") return jsonResponse({ ok: true });
        return jsonResponse({ ok: true });
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("should show a scannable code, confirm it and hand out recovery codes", async () => {
    const done = vi.fn();
    const { root, app } = mount(MfaSetup, { username: "ana", onDone: done });
    await flush();
    expect(byTestId(root, "mfa-qr").innerHTML).toContain("<svg");
    expect(byTestId(root, "mfa-secret").textContent).toBe("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP");

    typeInto(byTestId<HTMLInputElement>(root, "mfa-setup-code"), "000000");
    await nextTick();
    byTestId<HTMLButtonElement>(root, "mfa-setup-confirm").closest("form")!.dispatchEvent(new Event("submit"));
    await flush();
    expect(byTestId(root, "mfa-setup-error").textContent).toContain("mfa.errors.codeInvalid");

    typeInto(byTestId<HTMLInputElement>(root, "mfa-setup-code"), "123456");
    await nextTick();
    byTestId<HTMLButtonElement>(root, "mfa-setup-confirm").closest("form")!.dispatchEvent(new Event("submit"));
    await flush();
    expect(requests.filter((request) => request.path === "auth/mfa/confirm").at(-1)?.body).toEqual({ code: "123456" });
    expect(byTestId(root, "mfa-recovery-codes").textContent).toContain("aaaaa-bbbbb");
    byTestId<HTMLButtonElement>(root, "mfa-setup-done").click();
    expect(done).toHaveBeenCalledTimes(1);
    app.unmount();
  });

  it("should let a user turn two-factor off unless an administrator requires it", async () => {
    status = { enabled: true, required: false, setup_required: false, recovery_codes_left: 8 };
    const { root, app } = mount(MfaAccountCard, { username: "ana" });
    await flush();
    expect(byTestId(root, "mfa-account-status").textContent).toContain('mfa.statusEnabled:{"count":8}');
    byTestId<HTMLButtonElement>(root, "mfa-account-disable").click();
    await flush();
    const form = byTestId<HTMLFormElement>(root, "mfa-disable-form");
    typeInto(form.querySelector<HTMLInputElement>('input[type="password"]')!, "ana-password");
    typeInto(byTestId<HTMLInputElement>(form, "mfa-disable-code"), "aaaaa-bbbbb");
    await nextTick();
    form.dispatchEvent(new Event("submit"));
    await flush();
    expect(requests.find((request) => request.path === "auth/mfa/disable")?.body).toEqual({ password: "ana-password", code: "aaaaa-bbbbb" });
    app.unmount();

    status = { enabled: true, required: true, setup_required: false, recovery_codes_left: 8 };
    const required = mount(MfaAccountCard, { username: "ana" });
    await flush();
    expect(required.root.querySelector('[data-testid="mfa-account-disable"]')).toBeNull();
    expect(required.root.textContent).toContain("mfa.requiredByAdmin");
    required.app.unmount();
  });

  it("should remember a dismissed recommendation per user, and only for the session for administrators", () => {
    const memoryStorage = () => {
      const values = new Map<string, string>();
      return { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => void values.set(key, value), removeItem: (key: string) => void values.delete(key), clear: () => values.clear(), key: () => null, length: 0 };
    };
    vi.stubGlobal("localStorage", memoryStorage());
    vi.stubGlobal("sessionStorage", memoryStorage());
    expect(mfaRecommendationDismissed("u1", false)).toBe(false);
    dismissMfaRecommendation("u1", false);
    dismissMfaRecommendation("root", true);
    expect(mfaRecommendationDismissed("u1", false)).toBe(true);
    expect(mfaRecommendationDismissed("u2", false)).toBe(false);
    expect(window.localStorage.getItem("dbx-mfa-recommendation-dismissed:root")).toBeNull();
    expect(mfaRecommendationDismissed("root", true)).toBe(true);
  });
});
