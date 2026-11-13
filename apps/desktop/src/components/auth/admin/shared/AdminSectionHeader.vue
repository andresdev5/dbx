<script setup lang="ts">
defineProps<{ title: string; description?: string }>();
</script>

<template>
  <header class="flex flex-wrap items-start justify-between gap-3">
    <div class="min-w-0 space-y-1">
      <slot name="before-title" />
      <h2 class="text-lg font-semibold tracking-tight">{{ title }}</h2>
      <p v-if="description" class="max-w-3xl text-sm text-muted-foreground">{{ description }}</p>
    </div>
    <div class="flex shrink-0 flex-wrap items-center gap-2">
      <slot name="actions" />
    </div>
  </header>
</template>
