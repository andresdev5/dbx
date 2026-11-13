export type ExternalCaptchaProvider = "cap" | "turnstile" | "hcaptcha" | "recaptcha";

export interface ExternalCaptchaChallenge {
  provider: ExternalCaptchaProvider;
  site_key: string;
  endpoint?: string | null;
}

interface WidgetApi {
  render(container: HTMLElement, options: Record<string, unknown>): unknown;
  reset?(id?: unknown): void;
  ready?(callback: () => void): void;
}

const SCRIPTS: Record<Exclude<ExternalCaptchaProvider, "cap">, { url: string; global: string }> = {
  turnstile: { url: "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit", global: "turnstile" },
  hcaptcha: { url: "https://js.hcaptcha.com/1/api.js?render=explicit", global: "hcaptcha" },
  recaptcha: { url: "https://www.google.com/recaptcha/api.js?render=explicit", global: "grecaptcha" },
};

const loading = new Map<string, Promise<void>>();

export function isExternalCaptcha(value: unknown): value is ExternalCaptchaChallenge {
  if (!value || typeof value !== "object") return false;
  const challenge = value as Record<string, unknown>;
  return ["cap", "turnstile", "hcaptcha", "recaptcha"].includes(String(challenge.provider)) && typeof challenge.site_key === "string";
}

function loadScript(url: string, ready: () => boolean): Promise<void> {
  if (ready()) return Promise.resolve();
  const pending = loading.get(url);
  if (pending) return pending;
  const promise = new Promise<void>((resolve, reject) => {
    const script = document.createElement("script");
    script.src = url;
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => {
      loading.delete(url);
      reject(new Error("captcha_widget_unavailable"));
    };
    document.head.append(script);
  });
  loading.set(url, promise);
  return promise;
}

function widgetApi(global: string): WidgetApi | undefined {
  return (window as unknown as Record<string, WidgetApi | undefined>)[global];
}

async function waitFor(global: string): Promise<WidgetApi> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const api = widgetApi(global);
    if (api?.render) return api;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("captcha_widget_unavailable");
}

export interface RenderedCaptcha {
  reset(): void;
}

export async function renderExternalCaptcha(container: HTMLElement, challenge: ExternalCaptchaChallenge, onToken: (token: string) => void, onExpired: () => void): Promise<RenderedCaptcha> {
  if (challenge.provider === "cap") {
    const endpoint = challenge.endpoint ?? "";
    if (!customElements.get("cap-widget")) await loadScript(new URL("/assets/widget.js", endpoint).toString(), () => Boolean(customElements.get("cap-widget")));
    const widget = document.createElement("cap-widget");
    widget.setAttribute("data-cap-api-endpoint", endpoint);
    widget.addEventListener("solve", (event) => onToken(String((event as CustomEvent<{ token?: string }>).detail?.token ?? "")));
    widget.addEventListener("reset", onExpired);
    container.replaceChildren(widget);
    return { reset: () => (widget as unknown as { reset?: () => void }).reset?.() };
  }
  const script = SCRIPTS[challenge.provider];
  await loadScript(script.url, () => Boolean(widgetApi(script.global)?.render));
  const api = await waitFor(script.global);
  if (api.ready) await new Promise<void>((resolve) => api.ready!(resolve));
  const id = api.render(container, { sitekey: challenge.site_key, callback: (token: string) => onToken(token), "expired-callback": onExpired, "error-callback": onExpired });
  return { reset: () => api.reset?.(id) };
}
