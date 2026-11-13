<script setup lang="ts">
import type { HTMLAttributes } from "vue";
import { Search, X } from "@lucide/vue";
import { cn } from "@/lib/common/utils";

const props = defineProps<{ placeholder: string; class?: HTMLAttributes["class"] }>();
const model = defineModel<string>({ required: true });
</script>

<template>
  <div :class="cn('relative w-full sm:w-64', props.class)">
    <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
    <input
      v-model="model"
      type="search"
      autocomplete="off"
      spellcheck="false"
      data-admin-console-search
      data-testid="admin-search"
      :placeholder="placeholder"
      class="h-8 w-full rounded-md border border-input bg-transparent pl-8 pr-7 text-sm outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30 [&::-webkit-search-cancel-button]:hidden"
    />
    <button v-if="model" type="button" class="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground" :aria-label="placeholder" @click="model = ''">
      <X class="h-3.5 w-3.5" />
    </button>
  </div>
</template>
