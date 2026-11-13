<script setup lang="ts">
import { computed } from "vue";

const props = withDefaults(defineProps<{ name: string; size?: "sm" | "lg"; muted?: boolean }>(), { size: "sm", muted: false });

const PALETTE = [
  "bg-sky-500/15 text-sky-700 dark:text-sky-300",
  "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
  "bg-violet-500/15 text-violet-700 dark:text-violet-300",
  "bg-amber-500/15 text-amber-700 dark:text-amber-300",
  "bg-rose-500/15 text-rose-700 dark:text-rose-300",
  "bg-teal-500/15 text-teal-700 dark:text-teal-300",
];

const initials = computed(() => {
  const parts = props.name
    .trim()
    .split(/[\s._-]+/)
    .filter(Boolean);
  const letters = parts.length > 1 ? `${parts[0]![0]}${parts[1]![0]}` : (parts[0] ?? "?").slice(0, 2);
  return letters.toUpperCase();
});

const colorClass = computed(() => {
  if (props.muted) return "bg-muted text-muted-foreground";
  let hash = 0;
  for (const char of props.name) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return PALETTE[hash % PALETTE.length];
});
</script>

<template>
  <span :class="['inline-flex shrink-0 select-none items-center justify-center rounded-full font-semibold', size === 'lg' ? 'h-12 w-12 text-base' : 'h-7 w-7 text-[11px]', colorClass]" aria-hidden="true">{{ initials }}</span>
</template>
