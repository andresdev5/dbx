import type { GlobalNavigationEntry } from "./navigationEntry";

export interface GlobalNavigationExecutorHandlers {
  restoreQuery: (entry: GlobalNavigationEntry) => Promise<boolean>;
  activateSettings: () => void;
  activateDriverStore: () => void;
  activatePluginCenter: () => void;
  activateAdminConsole?: () => void;
}

export async function restoreGlobalNavigationEntry(entry: GlobalNavigationEntry, handlers: GlobalNavigationExecutorHandlers): Promise<boolean> {
  switch (entry.surface) {
    case "query":
      return handlers.restoreQuery(entry);
    case "settings":
      handlers.activateSettings();
      return true;
    case "driverStore":
      handlers.activateDriverStore();
      return true;
    case "pluginCenter":
      handlers.activatePluginCenter();
      return true;
    case "adminConsole":
      if (!handlers.activateAdminConsole) return false;
      handlers.activateAdminConsole();
      return true;
    default:
      return false;
  }
}
