import { inject, type InjectionKey } from "vue";

export type AdminSection = "users" | "groups" | "roles" | "grants" | "effective" | "functions" | "sessions" | "audit" | "identity" | "policies";

export type AdminRoute = { section: AdminSection; userId?: string } | { section: "user"; id: string; tab?: string } | { section: "group"; id: string; tab?: string };

export interface AdminNavGroup {
  key: string;
  sections: AdminSection[];
}

export const ADMIN_NAV: AdminNavGroup[] = [
  { key: "identity", sections: ["users", "groups"] },
  { key: "access", sections: ["roles", "grants", "effective", "functions"] },
  { key: "activity", sections: ["sessions", "audit"] },
  { key: "authentication", sections: ["identity", "policies"] },
];

export function routeSection(route: AdminRoute): AdminSection {
  if (route.section === "user") return "users";
  if (route.section === "group") return "groups";
  return route.section;
}

export interface AdminNavigator {
  go: (route: AdminRoute) => void;
}

export const ADMIN_NAVIGATOR: InjectionKey<AdminNavigator> = Symbol("dbx:admin-navigator");

export function useAdminNavigator(): AdminNavigator {
  return inject(ADMIN_NAVIGATOR, { go: () => undefined });
}
