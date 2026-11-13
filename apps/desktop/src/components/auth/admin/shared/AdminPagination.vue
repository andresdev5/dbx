<script setup lang="ts">
import { computed } from "vue";
import { useI18n } from "vue-i18n";
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { PAGE_SIZES, pageRange, pageWindow } from "@/lib/auth/adminTable";

const props = withDefaults(defineProps<{ page: number; pageCount: number; pageSize: number; total: number; pageSizes?: readonly number[] }>(), { pageSizes: () => PAGE_SIZES });
const emit = defineEmits<{ "update:page": [page: number]; "update:pageSize": [size: number] }>();
const { t } = useI18n();

const range = computed(() => pageRange(props.page, props.pageSize, props.total));
const pages = computed(() => pageWindow(props.page, props.pageCount));

function go(page: number) {
  const next = Math.min(Math.max(1, page), props.pageCount);
  if (next !== props.page) emit("update:page", next);
}
</script>

<template>
  <div class="flex flex-wrap items-center justify-between gap-3 border-t border-border/70 bg-muted/20 px-3 py-2 text-xs text-muted-foreground" data-testid="admin-pagination">
    <div class="flex items-center gap-3">
      <span data-testid="admin-pagination-range">{{ t("adminConsole.table.range", { from: range.from, to: range.to, total }) }}</span>
      <label class="flex items-center gap-1.5">
        {{ t("adminConsole.table.perPage") }}
        <select class="h-7 rounded-md border border-input bg-background px-1.5 text-xs text-foreground" :value="pageSize" data-testid="admin-pagination-size" @change="emit('update:pageSize', Number(($event.target as HTMLSelectElement).value))">
          <option v-for="size in pageSizes" :key="size" :value="size">{{ size }}</option>
        </select>
      </label>
    </div>
    <nav v-if="pageCount > 1" class="flex items-center gap-1" :aria-label="t('adminConsole.table.pagination')">
      <Button variant="ghost" size="icon-xs" :disabled="page <= 1" :aria-label="t('adminConsole.table.first')" @click="go(1)"><ChevronsLeft /></Button>
      <Button variant="ghost" size="icon-xs" :disabled="page <= 1" :aria-label="t('adminConsole.table.previous')" data-testid="admin-pagination-previous" @click="go(page - 1)"><ChevronLeft /></Button>
      <template v-for="(item, index) in pages" :key="`${item}-${index}`">
        <span v-if="item === 'gap'" class="px-1">…</span>
        <Button v-else :variant="item === page ? 'secondary' : 'ghost'" size="xs" class="min-w-6 tabular-nums" :aria-current="item === page ? 'page' : undefined" :data-testid="`admin-pagination-page-${item}`" @click="go(item)">{{ item }}</Button>
      </template>
      <Button variant="ghost" size="icon-xs" :disabled="page >= pageCount" :aria-label="t('adminConsole.table.next')" data-testid="admin-pagination-next" @click="go(page + 1)"><ChevronRight /></Button>
      <Button variant="ghost" size="icon-xs" :disabled="page >= pageCount" :aria-label="t('adminConsole.table.last')" @click="go(pageCount)"><ChevronsRight /></Button>
    </nav>
  </div>
</template>
