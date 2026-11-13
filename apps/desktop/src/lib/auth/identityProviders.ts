import { apiUrl } from "@/lib/common/webPath";
import { readAuthErrorCode } from "@/lib/startup/startupAuthentication";

export type IdentityProviderKind = "oidc" | "ldap";

export interface PublicIdentityProvider {
  id: string;
  name: string;
  kind: IdentityProviderKind;
}

export interface IdentityProvider {
  id: string;
  kind: IdentityProviderKind;
  name: string;
  config: Record<string, unknown>;
  auto_create_users: boolean;
  default_group_id: string | null;
  enabled: boolean;
  has_secret: boolean;
}

export interface IdentityProviderDraft {
  id?: string;
  kind: IdentityProviderKind;
  name: string;
  config: Record<string, unknown>;
  auto_create_users: boolean;
  default_group_id: string | null;
  enabled: boolean;
  secret?: string;
}

export class IdentityProviderError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

async function post<T>(path: string, body: unknown = {}): Promise<T> {
  const response = await fetch(apiUrl(`/api/admin/identity-providers/${path}`), {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new IdentityProviderError(await readAuthErrorCode(response));
  return (await response.json()) as T;
}

export const identityProviders = {
  list: () => post<IdentityProvider[]>("list"),
  save: (draft: IdentityProviderDraft) => post<IdentityProvider>("save", draft),
  remove: (id: string) => post("delete", { id }),
  test: (id: string) => post<{ ok: boolean; detail?: string }>("test", { id }),
};

export async function publicIdentityProviders(): Promise<PublicIdentityProvider[]> {
  try {
    const response = await fetch(apiUrl("/api/auth/providers"), { credentials: "same-origin" });
    if (!response.ok) return [];
    const body = (await response.json()) as unknown;
    return Array.isArray(body) ? (body as PublicIdentityProvider[]) : [];
  } catch {
    return [];
  }
}

export function oidcStartUrl(id: string): string {
  return apiUrl(`/api/auth/oidc/${encodeURIComponent(id)}/start`);
}

export function oidcCallbackUrl(): string {
  return new URL(apiUrl("/api/auth/oidc/callback"), window.location.origin).toString();
}

export function takeSsoError(): string {
  try {
    const url = new URL(window.location.href);
    const code = url.searchParams.get("sso_error");
    if (!code) return "";
    url.searchParams.delete("sso_error");
    window.history.replaceState(null, "", url.pathname + url.search + url.hash);
    return /^[a-z_]{1,64}$/.test(code) ? code : "";
  } catch {
    return "";
  }
}
