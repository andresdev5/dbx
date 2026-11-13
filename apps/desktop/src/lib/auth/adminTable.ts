import { computed, ref, watch, type Ref } from "vue";

export type SortDirection = "asc" | "desc";
export type SortValue = string | number | boolean | null | undefined;

export const PAGE_SIZES = [10, 20, 50, 100] as const;
export const DEFAULT_PAGE_SIZE = 20;

export interface TableStateOptions<T> {
  pageSize?: number;
  matches?: (row: T, query: string) => boolean;
  filter?: (row: T) => boolean;
  sorters?: Record<string, (row: T) => SortValue>;
  initialSort?: { key: string; direction: SortDirection };
}

export function normalizeSearch(value: string): string {
  return value.trim().toLocaleLowerCase();
}

export function textMatches(query: string, ...values: (string | null | undefined)[]): boolean {
  if (!query) return true;
  return values.some((value) => typeof value === "string" && value.toLocaleLowerCase().includes(query));
}

function isMissing(value: SortValue): boolean {
  return value === null || value === undefined || value === "";
}

export function compareValues(left: SortValue, right: SortValue): number {
  const leftMissing = isMissing(left);
  const rightMissing = isMissing(right);
  if (leftMissing || rightMissing) return leftMissing === rightMissing ? 0 : leftMissing ? 1 : -1;
  if (typeof left === "number" && typeof right === "number") return left - right;
  if (typeof left === "boolean" && typeof right === "boolean") return Number(left) - Number(right);
  return String(left).localeCompare(String(right), undefined, { numeric: true, sensitivity: "base" });
}

export function pageCountFor(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / Math.max(1, pageSize)));
}

export function pageRange(page: number, pageSize: number, total: number): { from: number; to: number } {
  if (total <= 0) return { from: 0, to: 0 };
  const from = (page - 1) * pageSize + 1;
  return { from: Math.min(from, total), to: Math.min(page * pageSize, total) };
}

export function pageWindow(current: number, count: number, siblings = 1): (number | "gap")[] {
  if (count <= 5 + siblings * 2) return Array.from({ length: count }, (_, index) => index + 1);
  const start = Math.max(2, current - siblings);
  const end = Math.min(count - 1, current + siblings);
  const pages: (number | "gap")[] = [1];
  if (start > 2) pages.push("gap");
  for (let page = start; page <= end; page += 1) pages.push(page);
  if (end < count - 1) pages.push("gap");
  pages.push(count);
  return pages;
}

export function useTableState<T>(rows: Ref<T[]>, options: TableStateOptions<T> = {}) {
  const query = ref("");
  const page = ref(1);
  const pageSize = ref(options.pageSize ?? DEFAULT_PAGE_SIZE);
  const sortKey = ref(options.initialSort?.key ?? "");
  const sortDirection = ref<SortDirection>(options.initialSort?.direction ?? "asc");

  const filtered = computed(() => {
    const needle = normalizeSearch(query.value);
    return rows.value.filter((row) => (!options.filter || options.filter(row)) && (!needle || !options.matches || options.matches(row, needle)));
  });

  const sorted = computed(() => {
    const sorter = sortKey.value ? options.sorters?.[sortKey.value] : undefined;
    if (!sorter) return filtered.value;
    const direction = sortDirection.value === "asc" ? 1 : -1;
    return [...filtered.value].sort((left, right) => {
      const leftValue = sorter(left);
      const rightValue = sorter(right);
      if (isMissing(leftValue) || isMissing(rightValue)) return compareValues(leftValue, rightValue);
      return compareValues(leftValue, rightValue) * direction;
    });
  });

  const total = computed(() => sorted.value.length);
  const pageCount = computed(() => pageCountFor(total.value, pageSize.value));
  const paged = computed(() => {
    const start = (page.value - 1) * pageSize.value;
    return sorted.value.slice(start, start + pageSize.value);
  });

  watch([query, pageSize], () => {
    page.value = 1;
  });
  watch(pageCount, (count) => {
    if (page.value > count) page.value = count;
  });

  function toggleSort(key: string) {
    if (sortKey.value === key) {
      sortDirection.value = sortDirection.value === "asc" ? "desc" : "asc";
      return;
    }
    sortKey.value = key;
    sortDirection.value = "asc";
  }

  return { query, page, pageSize, sortKey, sortDirection, filtered, sorted, paged, total, pageCount, toggleSort };
}
