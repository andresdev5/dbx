import { ref } from "vue";
import { useI18n } from "vue-i18n";
import { Eye, KeyRound, Pencil, ShieldAlert, ShieldOff, Trash2, UserRoundCheck, UserRoundX } from "@lucide/vue";
import { userAdmin, type ManagedUser } from "@/lib/auth/accessAdmin";
import { useAdminConfirm } from "@/lib/auth/adminConfirm";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import type { AdminRowAction } from "../shared/AdminRowMenu.vue";
import { useAdminText } from "../shared/adminUi";

export interface IssuedPassword {
  username: string;
  password: string;
}

export function useUserActions() {
  const { t } = useI18n();
  const { errorText } = useAdminText();
  const directory = useAdminDirectory();
  const confirm = useAdminConfirm();

  const busyId = ref("");
  const error = ref("");
  const issued = ref<IssuedPassword | null>(null);

  async function run(user: ManagedUser, action: () => Promise<void>): Promise<boolean> {
    busyId.value = user.id;
    error.value = "";
    try {
      await action();
      return true;
    } catch (e) {
      error.value = errorText(e);
      return false;
    } finally {
      busyId.value = "";
    }
  }

  function isSelf(user: ManagedUser): boolean {
    return user.id === directory.currentUserId.value;
  }

  async function toggleActive(user: ManagedUser) {
    if (user.active && !(await confirm({ title: t("adminConsole.users.confirm.disableTitle", { username: user.username }), description: t("adminConsole.users.confirm.disableDescription"), confirmLabel: t("adminConsole.users.actions.disable"), destructive: true }))) return;
    await run(user, async () => directory.replaceUser(await userAdmin.setActive(user.id, !user.active)));
  }

  async function resetPassword(user: ManagedUser) {
    if (!(await confirm({ title: t("adminConsole.users.confirm.resetPasswordTitle", { username: user.username }), description: t("adminConsole.users.confirm.resetPasswordDescription"), confirmLabel: t("adminConsole.users.actions.resetPassword") }))) return;
    await run(user, async () => {
      const result = await userAdmin.resetPassword(user.id);
      directory.replaceUser(result.user);
      if (result.temporary_password) issued.value = { username: user.username, password: result.temporary_password };
    });
  }

  async function toggleMfaRequired(user: ManagedUser) {
    await run(user, async () => directory.replaceUser(await userAdmin.setMfaRequired(user.id, !user.mfa_required)));
  }

  async function resetMfa(user: ManagedUser) {
    if (!(await confirm({ title: t("adminConsole.users.confirm.resetMfaTitle", { username: user.username }), description: t("adminConsole.users.confirm.resetMfaDescription"), confirmLabel: t("adminConsole.users.actions.resetMfa"), destructive: true }))) return;
    await run(user, async () => directory.replaceUser(await userAdmin.resetMfa(user.id)));
  }

  async function remove(user: ManagedUser): Promise<boolean> {
    if (!(await confirm({ title: t("adminConsole.users.confirm.deleteTitle", { username: user.username }), description: t("adminConsole.users.confirm.deleteDescription"), confirmLabel: t("adminConsole.users.actions.delete"), destructive: true }))) return false;
    const removed = await run(user, async () => {
      await userAdmin.remove(user.id);
      directory.users.value = directory.users.value.filter((candidate) => candidate.id !== user.id);
    });
    if (removed) void directory.refreshGroups();
    return removed;
  }

  function actionsFor(user: ManagedUser, handlers: { view?: () => void; edit?: () => void }): AdminRowAction[] {
    const actions: AdminRowAction[] = [];
    if (handlers.view) actions.push({ key: "view", label: t("adminConsole.users.actions.view"), icon: Eye, action: handlers.view });
    if (handlers.edit) actions.push({ key: "edit", label: t("adminConsole.users.actions.edit"), icon: Pencil, action: handlers.edit });
    if (isSelf(user)) return actions;
    actions.push(
      { key: "separator-security", separator: true },
      { key: "reset-password", label: t("adminConsole.users.actions.resetPassword"), icon: KeyRound, action: () => void resetPassword(user) },
      { key: "toggle-mfa-required", label: user.mfa_required ? t("adminConsole.users.actions.unrequireMfa") : t("adminConsole.users.actions.requireMfa"), icon: ShieldAlert, action: () => void toggleMfaRequired(user) },
    );
    if (user.mfa_enabled) actions.push({ key: "reset-mfa", label: t("adminConsole.users.actions.resetMfa"), icon: ShieldOff, action: () => void resetMfa(user) });
    actions.push(
      { key: "separator-danger", separator: true },
      user.active ? { key: "disable", label: t("adminConsole.users.actions.disable"), icon: UserRoundX, action: () => void toggleActive(user) } : { key: "enable", label: t("adminConsole.users.actions.enable"), icon: UserRoundCheck, action: () => void toggleActive(user) },
      { key: "delete", label: t("adminConsole.users.actions.delete"), icon: Trash2, destructive: true, action: () => void remove(user) },
    );
    return actions;
  }

  return { busyId, error, issued, isSelf, toggleActive, resetPassword, toggleMfaRequired, resetMfa, remove, actionsFor };
}
