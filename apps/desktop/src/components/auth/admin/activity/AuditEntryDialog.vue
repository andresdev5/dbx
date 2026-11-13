<script setup lang="ts">
import { ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Eye, Loader2, Lock } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { auditAdmin, type AuditEntry } from "@/lib/auth/auditAdmin";
import AdminBadge from "../shared/AdminBadge.vue";
import { useAdminText } from "../shared/adminUi";

const props = defineProps<{ entry: AuditEntry | null; eventLabel: string; actor: string; target: string }>();
const emit = defineEmits<{ close: [] }>();
const { t } = useI18n();
const { dateTime, errorText } = useAdminText();

const revealed = ref<Record<string, string>>({});
const revealing = ref(false);
const error = ref("");

watch(
  () => props.entry?.event_id,
  () => {
    error.value = "";
  },
);

async function reveal() {
  const entry = props.entry;
  if (!entry) return;
  revealing.value = true;
  error.value = "";
  try {
    revealed.value = { ...revealed.value, [entry.event_id]: await auditAdmin.reveal(entry.event_id) };
  } catch (e) {
    error.value = errorText(e);
  } finally {
    revealing.value = false;
  }
}
</script>

<template>
  <Dialog :open="entry !== null" @update:open="(open: boolean) => !open && emit('close')">
    <DialogContent class="sm:max-w-2xl">
      <DialogHeader>
        <DialogTitle class="flex flex-wrap items-center gap-2">
          {{ t("adminConsole.audit.detail.title") }}
          <AdminBadge v-if="entry?.decision" :tone="entry.decision === 'deny' ? 'danger' : 'success'">{{ entry.decision === "deny" ? t("audit.denied") : t("audit.allowed") }}</AdminBadge>
        </DialogTitle>
      </DialogHeader>
      <div v-if="entry" class="max-h-[65vh] space-y-4 overflow-y-auto pr-1 text-sm" data-testid="audit-entry-detail">
        <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
          <dt class="text-muted-foreground">{{ t("audit.event") }}</dt>
          <dd class="font-medium">{{ eventLabel }}</dd>
          <dt class="text-muted-foreground">{{ t("adminConsole.audit.detail.when") }}</dt>
          <dd>{{ dateTime(entry.ts) }}</dd>
          <dt class="text-muted-foreground">{{ t("adminConsole.audit.detail.actor") }}</dt>
          <dd>{{ actor }}</dd>
          <template v-if="target">
            <dt class="text-muted-foreground">{{ t("adminConsole.audit.detail.target") }}</dt>
            <dd class="break-words">{{ target }}</dd>
          </template>
          <template v-if="entry.operations.length">
            <dt class="text-muted-foreground">{{ t("adminConsole.audit.detail.operations") }}</dt>
            <dd class="flex flex-wrap gap-1">
              <AdminBadge v-for="operation in entry.operations" :key="operation" mono>{{ operation }}</AdminBadge>
            </dd>
          </template>
          <template v-if="entry.reason">
            <dt class="text-muted-foreground">{{ t("audit.reason") }}</dt>
            <dd class="break-words">{{ entry.reason }}</dd>
          </template>
          <template v-if="entry.ip">
            <dt class="text-muted-foreground">{{ t("audit.ip") }}</dt>
            <dd class="font-mono text-xs">{{ entry.ip }}</dd>
          </template>
          <template v-if="entry.session_ref">
            <dt class="text-muted-foreground">{{ t("audit.session") }}</dt>
            <dd class="font-mono text-xs">{{ entry.session_ref }}</dd>
          </template>
          <template v-if="entry.rows_affected !== null">
            <dt class="text-muted-foreground">{{ t("audit.rowsAffected") }}</dt>
            <dd data-testid="audit-rows">{{ entry.rows_affected }}</dd>
          </template>
          <template v-if="entry.duration_ms !== null">
            <dt class="text-muted-foreground">{{ t("audit.duration") }}</dt>
            <dd>{{ t("audit.durationMs", { ms: entry.duration_ms }) }}</dd>
          </template>
          <dt class="text-muted-foreground">{{ t("audit.eventId") }}</dt>
          <dd class="font-mono text-xs">{{ entry.event_id }}</dd>
        </dl>

        <div v-if="entry.has_statement" class="space-y-2 rounded-lg border border-border/70 p-3">
          <p class="text-xs font-medium text-muted-foreground">{{ t("adminConsole.audit.detail.statement") }}</p>
          <pre v-if="revealed[entry.event_id] !== undefined" class="overflow-x-auto whitespace-pre-wrap rounded-md bg-muted/50 p-2 font-mono text-xs" data-testid="audit-statement-text">{{ revealed[entry.event_id] }}</pre>
          <div v-else class="flex flex-wrap items-center gap-3">
            <span class="flex items-center gap-1.5 text-muted-foreground"><Lock class="h-3.5 w-3.5" />{{ t("audit.statementEncrypted") }}</span>
            <Button size="sm" variant="outline" :disabled="revealing" data-testid="audit-reveal" @click="reveal">
              <Loader2 v-if="revealing" class="animate-spin" />
              <Eye v-else />
              {{ t("audit.reveal") }}
            </Button>
          </div>
          <p class="text-xs text-muted-foreground">{{ t("audit.revealHint") }}</p>
          <p v-if="error" class="text-xs text-destructive">{{ error }}</p>
        </div>

        <div v-if="entry.detail" class="space-y-1.5">
          <p class="text-xs font-medium text-muted-foreground">{{ t("adminConsole.audit.detail.details") }}</p>
          <pre class="overflow-x-auto rounded-md bg-muted/50 p-2 font-mono text-xs">{{ JSON.stringify(entry.detail, null, 2) }}</pre>
        </div>
      </div>
    </DialogContent>
  </Dialog>
</template>
