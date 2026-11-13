import { describe, expect, it, vi } from "vitest";
import { restoreGlobalNavigationEntry } from "../globalNavigationExecutor";

describe("global navigation executor", () => {
  it("dispatches query and special-page entries to their handlers", async () => {
    const handlers = {
      restoreQuery: vi.fn(async () => true),
      activateSettings: vi.fn(),
      activateDriverStore: vi.fn(),
      activatePluginCenter: vi.fn(),
    };
    await restoreGlobalNavigationEntry({ id: "q", surface: "query", tabId: "tab-1" }, handlers);
    await restoreGlobalNavigationEntry({ id: "s", surface: "settings" }, handlers);
    expect(handlers.restoreQuery).toHaveBeenCalledWith({ id: "q", surface: "query", tabId: "tab-1" });
    expect(handlers.activateSettings).toHaveBeenCalledOnce();
  });

  it("should restore the administration page only when a handler is available", async () => {
    const activateAdminConsole = vi.fn();
    const base = { restoreQuery: async () => false, activateSettings: () => {}, activateDriverStore: () => {}, activatePluginCenter: () => {} };
    expect(await restoreGlobalNavigationEntry({ id: "a", surface: "adminConsole" }, { ...base, activateAdminConsole })).toBe(true);
    expect(activateAdminConsole).toHaveBeenCalledOnce();
    expect(await restoreGlobalNavigationEntry({ id: "a", surface: "adminConsole" }, base)).toBe(false);
  });

  it("reports a closed query tab as unrestorable", async () => {
    const restored = await restoreGlobalNavigationEntry({ id: "q", surface: "query", tabId: "closed" }, { restoreQuery: async () => false, activateSettings: () => {}, activateDriverStore: () => {}, activatePluginCenter: () => {} });
    expect(restored).toBe(false);
  });
});
