<script setup lang="ts">
import { ref } from "vue";
import { useI18n } from "vue-i18n";
import { AlertTriangle } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { AdminConfirmRequest } from "@/lib/auth/adminConfirm";

const { t } = useI18n();
const open = ref(false);
const request = ref<AdminConfirmRequest>({ title: "" });
let resolver: ((value: boolean) => void) | null = null;

function settle(value: boolean) {
  open.value = false;
  resolver?.(value);
  resolver = null;
}

function ask(next: AdminConfirmRequest): Promise<boolean> {
  resolver?.(false);
  request.value = next;
  open.value = true;
  return new Promise((resolve) => {
    resolver = resolve;
  });
}

defineExpose({ ask });
</script>

<template>
  <Dialog :open="open" @update:open="(value: boolean) => !value && settle(false)">
    <DialogContent class="sm:max-w-md" data-testid="admin-confirm">
      <DialogHeader>
        <DialogTitle class="flex items-center gap-2">
          <AlertTriangle v-if="request.destructive" class="h-5 w-5 shrink-0 text-destructive" />
          {{ request.title }}
        </DialogTitle>
        <DialogDescription v-if="request.description" class="text-sm text-muted-foreground">{{ request.description }}</DialogDescription>
      </DialogHeader>
      <DialogFooter>
        <Button variant="outline" data-testid="admin-confirm-cancel" @click="settle(false)">{{ t("common.cancel") }}</Button>
        <Button :variant="request.destructive ? 'destructive' : 'default'" data-testid="admin-confirm-accept" @click="settle(true)">{{ request.confirmLabel || t("adminConsole.confirm") }}</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
