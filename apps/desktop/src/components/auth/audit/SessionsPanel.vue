<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { LogOut, RefreshCw } from "@lucide/vue";
import { translateBackendError } from "@/i18n/backend-errors";
import { auditAdmin, type LiveSession } from "@/lib/auth/auditAdmin";

const { t } = useI18n();

const sessions = ref<LiveSession[]>([]);
const busy = ref(false);
const error = ref("");

const grouped = computed(() => {
  const groups = new Map<string, { userId: string; username: string; sessions: LiveSession[] }>();
  for (const session of sessions.value) {
    const group = groups.get(session.user_id) ?? { userId: session.user_id, username: session.username ?? session.user_id, sessions: [] };
    group.sessions.push(session);
    groups.set(session.user_id, group);
  }
  return [...groups.values()].sort((a, b) => a.username.localeCompare(b.username));
});

function errorText(e: unknown): string {
  return translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("users.actionFailed");
}

async function run(action: () => Promise<unknown>) {
  busy.value = true;
  error.value = "";
  try {
    await action();
    sessions.value = await auditAdmin.sessions();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}

function revoke(session: LiveSession) {
  if (!window.confirm(t("sessions.confirmRevoke", { username: session.username ?? session.user_id }))) return;
  void run(() => auditAdmin.revokeSession(session.id));
}

function revokeAll(userId: string, username: string) {
  if (!window.confirm(t("sessions.confirmRevokeAll", { username }))) return;
  void run(() => auditAdmin.revokeUserSessions(userId));
}

function formatTime(ts: number | null): string {
  return ts ? new Date(ts).toLocaleString() : t("sessions.noLimit");
}

function browser(userAgent: string | null): string {
  if (!userAgent) return t("sessions.unknownClient");
  return userAgent.length > 80 ? `${userAgent.slice(0, 80)}…` : userAgent;
}

onMounted(() => {
  void run(async () => undefined);
});
</script>

<template>
  <div class="space-y-3" data-testid="sessions-panel">
    <div class="flex items-start gap-2">
      <div class="flex-1 space-y-1">
        <Label class="text-base">{{ t("sessions.title") }}</Label>
        <p class="text-sm text-muted-foreground">{{ t("sessions.description") }}</p>
      </div>
      <Button variant="ghost" size="icon" class="h-8 w-8" :title="t('sessions.refresh')" :disabled="busy" @click="run(async () => undefined)">
        <RefreshCw class="h-4 w-4" />
      </Button>
    </div>
    <p v-if="error" class="text-sm text-destructive">{{ error }}</p>
    <p v-if="!grouped.length && !busy" class="text-sm text-muted-foreground">{{ t("sessions.empty") }}</p>
    <div v-for="group in grouped" :key="group.userId" class="overflow-hidden rounded-md border border-border/60" data-testid="sessions-user">
      <div class="flex items-center gap-2 border-b border-border/60 bg-muted/30 px-3 py-1.5">
        <p class="flex-1 truncate text-sm font-medium">{{ group.username }}</p>
        <Button v-if="group.sessions.some((session) => !session.current)" variant="ghost" size="sm" class="h-7 text-destructive hover:text-destructive" :disabled="busy" data-testid="sessions-revoke-all" @click="revokeAll(group.userId, group.username)">
          {{ t("sessions.revokeAll") }}
        </Button>
      </div>
      <div v-for="session in group.sessions" :key="session.id" class="flex items-center gap-2 border-b border-border/60 px-3 py-2 last:border-b-0" data-testid="session-row">
        <div class="min-w-0 flex-1">
          <p class="truncate text-sm">
            {{ session.ip ?? t("sessions.unknownIp") }}
            <span v-if="session.current" class="text-xs text-green-600"> · {{ t("sessions.current") }}</span>
          </p>
          <p class="truncate text-xs text-muted-foreground" :title="session.user_agent ?? ''">{{ browser(session.user_agent) }}</p>
          <p class="truncate text-xs text-muted-foreground">
            {{ t("sessions.started", { time: formatTime(session.created_at) }) }} · {{ t("sessions.lastSeen", { time: formatTime(session.last_seen_at) }) }} ·
            {{ t("sessions.expires", { time: formatTime(session.expires_at) }) }}
          </p>
        </div>
        <Button v-if="!session.current" variant="ghost" size="icon" class="h-8 w-8 text-destructive hover:text-destructive" :title="t('sessions.revoke')" :disabled="busy" data-testid="session-revoke" @click="revoke(session)">
          <LogOut class="h-4 w-4" />
        </Button>
      </div>
    </div>
  </div>
</template>
