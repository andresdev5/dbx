import { nextTick, ref } from "vue";
import { describe, expect, it } from "vitest";
import { compareValues, pageRange, pageWindow, textMatches, useTableState } from "@/lib/auth/adminTable";

interface Row {
  name: string;
  age: number | null;
  active: boolean;
}

function rows(count: number): Row[] {
  return Array.from({ length: count }, (_, index) => ({ name: `user${String(index + 1).padStart(2, "0")}`, age: index % 3 === 0 ? null : index, active: index % 2 === 0 }));
}

describe("admin table helpers", () => {
  it("should describe the visible range of a page", () => {
    expect(pageRange(1, 20, 57)).toEqual({ from: 1, to: 20 });
    expect(pageRange(3, 20, 57)).toEqual({ from: 41, to: 57 });
    expect(pageRange(1, 20, 0)).toEqual({ from: 0, to: 0 });
  });

  it("should collapse long page lists around the current page", () => {
    expect(pageWindow(1, 5)).toEqual([1, 2, 3, 4, 5]);
    expect(pageWindow(1, 20)).toEqual([1, 2, "gap", 20]);
    expect(pageWindow(10, 20)).toEqual([1, "gap", 9, 10, 11, "gap", 20]);
    expect(pageWindow(20, 20)).toEqual([1, "gap", 19, 20]);
  });

  it("should sort missing values last and compare numbers numerically", () => {
    expect([3, null, 10, 2].sort(compareValues)).toEqual([2, 3, 10, null]);
    expect(["user10", "user9"].sort(compareValues)).toEqual(["user9", "user10"]);
  });

  it("should match text case-insensitively across several fields", () => {
    expect(textMatches("ana", "Ana López", null)).toBe(true);
    expect(textMatches("bob", "Ana", "ana")).toBe(false);
    expect(textMatches("", "anything")).toBe(true);
  });
});

describe("useTableState", () => {
  it("should paginate, search and reset to the first page when the query changes", async () => {
    const source = ref(rows(45));
    const table = useTableState(source, { pageSize: 20, matches: (row, query) => textMatches(query, row.name) });

    expect(table.pageCount.value).toBe(3);
    table.page.value = 3;
    expect(table.paged.value.map((row) => row.name)).toEqual(["user41", "user42", "user43", "user44", "user45"]);

    table.query.value = "USER4";
    await nextTick();
    expect(table.page.value).toBe(1);
    expect(table.total.value).toBe(6);
  });

  it("should apply reactive filters and keep the page within range", async () => {
    const source = ref(rows(45));
    const onlyActive = ref(false);
    const table = useTableState(source, { pageSize: 10, filter: (row) => !onlyActive.value || row.active });

    table.page.value = 5;
    onlyActive.value = true;
    await nextTick();
    expect(table.total.value).toBe(23);
    expect(table.page.value).toBe(3);
  });

  it("should toggle the sort direction on the same column", () => {
    const source = ref(rows(5));
    const table = useTableState(source, { sorters: { age: (row) => row.age } });

    table.toggleSort("age");
    expect(table.sorted.value.map((row) => row.age)).toEqual([1, 2, 4, null, null]);
    table.toggleSort("age");
    expect(table.sortDirection.value).toBe("desc");
    expect(table.sorted.value.map((row) => row.age)).toEqual([4, 2, 1, null, null]);
  });
});
