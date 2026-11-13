<script setup lang="ts">
import type { Component } from "vue";
import { useI18n } from "vue-i18n";
import { MoreHorizontal } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

export interface AdminRowAction {
  key: string;
  label?: string;
  icon?: Component;
  action?: () => void;
  destructive?: boolean;
  disabled?: boolean;
  separator?: boolean;
}

defineProps<{ actions: AdminRowAction[]; disabled?: boolean }>();
const { t } = useI18n();
</script>

<template>
  <DropdownMenu>
    <DropdownMenuTrigger as-child>
      <Button variant="ghost" size="icon-sm" :disabled="disabled" :aria-label="t('adminConsole.table.actions')" data-row-action data-testid="admin-row-menu">
        <MoreHorizontal />
      </Button>
    </DropdownMenuTrigger>
    <DropdownMenuContent align="end" class="min-w-48">
      <template v-for="item in actions" :key="item.key">
        <DropdownMenuSeparator v-if="item.separator" />
        <DropdownMenuItem v-else :variant="item.destructive ? 'destructive' : 'default'" :disabled="item.disabled" :data-testid="`admin-action-${item.key}`" @select="item.action?.()">
          <component :is="item.icon" v-if="item.icon" class="h-4 w-4" />
          {{ item.label }}
        </DropdownMenuItem>
      </template>
    </DropdownMenuContent>
  </DropdownMenu>
</template>
