<script setup lang="ts" generic="T">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { ArrowDown, ArrowUp, ArrowUpDown, Inbox } from "@lucide/vue";
import { checkboxClass } from "./adminUi";

export interface AdminColumn {
  key: string;
  label: string;
  sortable?: boolean;
  align?: "left" | "right" | "center";
  class?: string;
  headerClass?: string;
}

const props = withDefaults(
  defineProps<{
    columns: AdminColumn[];
    rows: T[];
    rowKey: (row: T) => string;
    loading?: boolean;
    emptyText?: string;
    emptyHint?: string;
    selectable?: boolean;
    selected?: string[];
    sortKey?: string;
    sortDirection?: "asc" | "desc";
    clickable?: boolean;
    rowClass?: (row: T) => string;
    testId?: string;
  }>(),
  { loading: false, emptyText: "", emptyHint: "", selectable: false, selected: () => [], sortKey: "", sortDirection: "asc", clickable: false, rowClass: () => "", testId: "admin-table" },
);

const emit = defineEmits<{
  sort: [key: string];
  "row-click": [row: T];
  "update:selected": [ids: string[]];
}>();

const { t } = useI18n();

const pageIds = computed(() => props.rows.map((row) => props.rowKey(row)));
const allSelected = computed(() => pageIds.value.length > 0 && pageIds.value.every((id) => props.selected.includes(id)));
const someSelected = computed(() => !allSelected.value && pageIds.value.some((id) => props.selected.includes(id)));
const columnCount = computed(() => props.columns.length + (props.selectable ? 1 : 0));

function alignClass(align?: "left" | "right" | "center"): string {
  if (align === "right") return "text-right";
  if (align === "center") return "text-center";
  return "text-left";
}

function toggleAll() {
  if (allSelected.value) {
    emit(
      "update:selected",
      props.selected.filter((id) => !pageIds.value.includes(id)),
    );
    return;
  }
  emit("update:selected", [...new Set([...props.selected, ...pageIds.value])]);
}

function toggleRow(id: string) {
  emit("update:selected", props.selected.includes(id) ? props.selected.filter((candidate) => candidate !== id) : [...props.selected, id]);
}

function cellValue(row: T, key: string): unknown {
  return (row as Record<string, unknown>)[key];
}

function clickRow(row: T, event: MouseEvent) {
  if (!props.clickable) return;
  const target = event.target instanceof Element ? event.target : null;
  if (target?.closest("button, a, input, select, label, [role='menuitem'], [data-row-action]")) return;
  emit("row-click", row);
}
</script>

<template>
  <div class="overflow-hidden rounded-lg border border-border/70 bg-background" :data-testid="testId">
    <div class="overflow-x-auto">
      <table class="w-full min-w-full border-collapse text-sm">
        <thead class="bg-muted/40">
          <tr class="border-b border-border/70">
            <th v-if="selectable" class="w-10 px-3 py-2">
              <input type="checkbox" :class="checkboxClass" :checked="allSelected" :indeterminate="someSelected" :disabled="!rows.length" :aria-label="t('adminConsole.table.selectPage')" data-testid="admin-table-select-all" @change="toggleAll" />
            </th>
            <th v-for="column in columns" :key="column.key" scope="col" :class="['whitespace-nowrap px-3 py-2 text-xs font-medium text-muted-foreground', alignClass(column.align), column.headerClass]">
              <button v-if="column.sortable" type="button" class="inline-flex items-center gap-1 rounded hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50" :data-testid="`admin-sort-${column.key}`" @click="emit('sort', column.key)">
                {{ column.label }}
                <ArrowUp v-if="sortKey === column.key && sortDirection === 'asc'" class="h-3 w-3" />
                <ArrowDown v-else-if="sortKey === column.key" class="h-3 w-3" />
                <ArrowUpDown v-else class="h-3 w-3 opacity-40" />
              </button>
              <template v-else>{{ column.label }}</template>
            </th>
          </tr>
        </thead>
        <tbody>
          <template v-if="loading && !rows.length">
            <tr v-for="index in 5" :key="`skeleton-${index}`" class="border-b border-border/50 last:border-b-0">
              <td v-for="column in columnCount" :key="column" class="px-3 py-3">
                <div class="h-3 animate-pulse rounded bg-muted" :style="{ width: `${40 + ((index * 17 + column * 11) % 50)}%` }" />
              </td>
            </tr>
          </template>
          <tr v-else-if="!rows.length">
            <td :colspan="columnCount" class="px-3 py-10">
              <slot name="empty">
                <div class="flex flex-col items-center gap-2 text-center" data-testid="admin-table-empty">
                  <Inbox class="h-8 w-8 text-muted-foreground/50" />
                  <p class="text-sm font-medium">{{ emptyText || t("adminConsole.table.empty") }}</p>
                  <p v-if="emptyHint" class="max-w-sm text-xs text-muted-foreground">{{ emptyHint }}</p>
                </div>
              </slot>
            </td>
          </tr>
          <tr
            v-for="row in rows"
            v-else
            :key="rowKey(row)"
            :class="['border-b border-border/50 transition-colors last:border-b-0', clickable ? 'cursor-pointer hover:bg-muted/40' : 'hover:bg-muted/20', selected.includes(rowKey(row)) ? 'bg-primary/5' : '', rowClass(row)]"
            :data-testid="`${testId}-row`"
            @click="clickRow(row, $event)"
          >
            <td v-if="selectable" class="w-10 px-3 py-2">
              <input type="checkbox" :class="checkboxClass" :checked="selected.includes(rowKey(row))" :aria-label="t('adminConsole.table.selectRow')" data-row-action @change="toggleRow(rowKey(row))" />
            </td>
            <td v-for="column in columns" :key="column.key" :class="['px-3 py-2 align-middle', alignClass(column.align), column.class]">
              <slot :name="`cell-${column.key}`" :row="row">{{ cellValue(row, column.key) }}</slot>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <slot name="footer" />
  </div>
</template>
