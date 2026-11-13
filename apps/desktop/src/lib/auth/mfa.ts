import { renderSVG } from "uqr";
import { apiUrl } from "@/lib/common/webPath";
import { readAuthErrorCode } from "@/lib/startup/startupAuthentication";

export interface MfaStatus {
  enabled: boolean;
  required: boolean;
  setup_required: boolean;
  recovery_codes_left: number;
}

export interface MfaEnrollment {
  secret: string;
  otpauth_uri: string;
}

export class MfaError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

async function post<T>(path: string, body: unknown = {}): Promise<T> {
  const response = await fetch(apiUrl(`/api/${path}`), {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new MfaError(await readAuthErrorCode(response));
  return (await response.json()) as T;
}

export const mfa = {
  status: () => post<MfaStatus>("auth/mfa/status"),
  setup: () => post<MfaEnrollment>("auth/mfa/setup"),
  confirm: async (code: string) => (await post<{ recovery_codes: string[] }>("auth/mfa/confirm", { code })).recovery_codes,
  disable: (password: string, code: string) => post<{ ok: boolean }>("auth/mfa/disable", { password, code }),
  regenerateRecoveryCodes: async (code: string) => (await post<{ recovery_codes: string[] }>("auth/mfa/recovery-codes", { code })).recovery_codes,
  verifyLogin: (challenge: string, code: string) => post<{ must_change_password?: boolean; mfa_setup_required?: boolean }>("auth/mfa/verify", { challenge, code }),
};

export const mfaAdmin = {
  reset: (id: string) => post("admin/users/reset-mfa", { id }),
  setRequired: (id: string, required: boolean) => post("admin/users/set-mfa-required", { id, required }),
  policy: async () => (await post<{ required_all: boolean }>("admin/users/mfa-policy")).required_all,
  setPolicy: async (requiredAll: boolean) => (await post<{ required_all: boolean }>("admin/users/mfa-policy/save", { required_all: requiredAll })).required_all,
};

export function qrSvg(uri: string): string {
  return renderSVG(uri, { border: 2 });
}

export function recoveryCodesText(username: string, codes: string[]): string {
  return [`DBX ${username}`, "", ...codes, ""].join("\n");
}
