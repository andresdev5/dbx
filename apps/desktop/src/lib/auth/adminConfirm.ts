import { inject, type InjectionKey } from "vue";

export interface AdminConfirmRequest {
  title: string;
  description?: string;
  confirmLabel?: string;
  destructive?: boolean;
}

export type AdminConfirm = (request: AdminConfirmRequest) => Promise<boolean>;

export const ADMIN_CONFIRM: InjectionKey<AdminConfirm> = Symbol("dbx:admin-confirm");

export function useAdminConfirm(): AdminConfirm {
  return inject(ADMIN_CONFIRM, async (request) => window.confirm(request.description ? `${request.title}\n\n${request.description}` : request.title));
}
