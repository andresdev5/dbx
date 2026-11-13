import { afterEach, describe, expect, it, vi } from "vitest";

describe("sidebar layout persistence", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function stubResponse(status: number, body: unknown) {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("should keep the layout local when only administrators may change the shared groups", async () => {
    const fetchMock = stubResponse(403, { error: "admin_required" });
    const { saveSidebarLayout } = await import("@/lib/backend/http");
    await expect(saveSidebarLayout({ groups: [], order: [] })).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("should still report other failures", async () => {
    stubResponse(500, { error: "storage_failed" });
    const { saveSidebarLayout } = await import("@/lib/backend/http");
    await expect(saveSidebarLayout({ groups: [], order: [] })).rejects.toThrow();
  });
});
