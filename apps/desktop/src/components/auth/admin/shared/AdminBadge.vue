<script setup lang="ts">
import { computed } from "vue";

const props = withDefaults(defineProps<{ tone?: "success" | "warning" | "danger" | "info" | "neutral" | "primary"; dot?: boolean; mono?: boolean }>(), { tone: "neutral", dot: false, mono: false });

const toneClass = computed(
  () =>
    ({
      success: "bg-emerald-500/12 text-emerald-700 dark:text-emerald-400",
      warning: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
      danger: "bg-destructive/12 text-destructive",
      info: "bg-sky-500/12 text-sky-700 dark:text-sky-400",
      primary: "bg-primary/12 text-primary",
      neutral: "bg-muted text-muted-foreground",
    })[props.tone],
);
const dotClass = computed(
  () =>
    ({
      success: "bg-emerald-500",
      warning: "bg-amber-500",
      danger: "bg-destructive",
      info: "bg-sky-500",
      primary: "bg-primary",
      neutral: "bg-muted-foreground/60",
    })[props.tone],
);
</script>

<template>
  <span :class="['inline-flex h-5 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full px-2 text-[11px] font-medium leading-none', toneClass, mono ? 'font-mono' : '']">
    <span v-if="dot" :class="['h-1.5 w-1.5 rounded-full', dotClass]" />
    <slot />
  </span>
</template>
