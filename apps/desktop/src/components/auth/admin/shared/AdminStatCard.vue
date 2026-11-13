<script setup lang="ts">
import type { Component } from "vue";

defineProps<{ label: string; value: number | string; icon?: Component; tone?: "default" | "warning" | "success" }>();
</script>

<template>
  <div class="flex items-center gap-3 rounded-lg border border-border/70 bg-background px-3 py-2.5">
    <span v-if="icon" :class="['flex h-8 w-8 shrink-0 items-center justify-center rounded-md', tone === 'warning' ? 'bg-amber-500/12 text-amber-600 dark:text-amber-400' : tone === 'success' ? 'bg-emerald-500/12 text-emerald-600 dark:text-emerald-400' : 'bg-muted text-muted-foreground']">
      <component :is="icon" class="h-4 w-4" />
    </span>
    <div class="min-w-0">
      <p class="text-lg font-semibold leading-tight tabular-nums">{{ value }}</p>
      <p class="truncate text-xs text-muted-foreground">{{ label }}</p>
    </div>
  </div>
</template>
