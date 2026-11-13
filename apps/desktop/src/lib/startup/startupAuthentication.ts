import { apiUrl } from "@/lib/common/webPath";

export interface WebUser {
  id: string;
  username: string;
  display_name: string | null;
  role: "admin" | "user";
  must_change_password: boolean;
  mfa_setup_required: boolean;
  mfa_enabled: boolean;
}

export interface StartupAuthentication {
  required: boolean;
  authenticated: boolean;
  setup_required: boolean;
  user?: WebUser;
}

function parseWebUser(value: unknown): WebUser | undefined {
  if (!value || typeof value !== "object") return undefined;
  const user = value as Record<string, unknown>;
  if (typeof user.id !== "string" || typeof user.username !== "string") return undefined;
  return {
    id: user.id,
    username: user.username,
    display_name: typeof user.display_name === "string" ? user.display_name : null,
    role: user.role === "admin" ? "admin" : "user",
    must_change_password: user.must_change_password === true,
    mfa_setup_required: user.mfa_setup_required === true,
    mfa_enabled: user.mfa_enabled === true,
  };
}

export async function checkStartupAuthentication(signal?: AbortSignal): Promise<StartupAuthentication> {
  const response = await fetch(apiUrl("/api/auth/check"), { credentials: "same-origin", signal });
  if (!response.ok) throw new Error("AUTH_CHECK_FAILED");
  const result: unknown = await response.json();
  if (!result || typeof result !== "object" || !("required" in result) || !("authenticated" in result) || typeof result.required !== "boolean" || typeof result.authenticated !== "boolean") {
    throw new Error("AUTH_CHECK_FAILED");
  }
  return {
    required: result.required,
    authenticated: result.authenticated,
    setup_required: "setup_required" in result && result.setup_required === true,
    user: "user" in result ? parseWebUser(result.user) : undefined,
  };
}

export async function logoutWeb(): Promise<void> {
  const response = await fetch(apiUrl("/api/auth/logout"), {
    method: "POST",
    credentials: "same-origin",
  });
  if (!response.ok) {
    throw new Error("AUTH_LOGOUT_FAILED");
  }
}

export async function readAuthErrorCode(response: Response): Promise<string> {
  const text = (await response.text()).trim();
  if (!text) return "";
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed.error === "string") return parsed.error;
  } catch {
    return text;
  }
  return text;
}
