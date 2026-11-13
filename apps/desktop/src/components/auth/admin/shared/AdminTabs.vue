<script setup lang="ts">
defineProps<{ tabs: { key: string; label: string; count?: number }[] }>();
const model = defineModel<string>({ required: true });
</script>

<template>
  <div class="flex gap-1 overflow-x-auto border-b border-border/70" role="tablist">
    <button
      v-for="tab in tabs"
      :key="tab.key"
      type="button"
      role="tab"
      :aria-selected="model === tab.key"
      :class="['-mb-px flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-sm transition-colors focus-visible:outline-none', model === tab.key ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground']"
      :data-testid="`admin-tab-${tab.key}`"
      @click="model = tab.key"
    >
      {{ tab.label }}
      <span v-if="tab.count !== undefined" class="rounded-full bg-muted px-1.5 text-[11px] tabular-nums text-muted-foreground">{{ tab.count }}</span>
    </button>
  </div>
</template>
