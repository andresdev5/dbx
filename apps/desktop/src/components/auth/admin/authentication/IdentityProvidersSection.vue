<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Pencil, Plug, Plus, RefreshCw, Trash2 } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { useAdminConfirm } from "@/lib/auth/adminConfirm";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { identityProviders, type IdentityProvider } from "@/lib/auth/identityProviders";
import AdminBadge from "../shared/AdminBadge.vue";
import AdminDataTable, { type AdminColumn } from "../shared/AdminDataTable.vue";
import AdminRowMenu from "../shared/AdminRowMenu.vue";
import AdminSectionHeader from "../shared/AdminSectionHeader.vue";
import { useAdminText } from "../shared/adminUi";
import IdentityProviderFormDialog from "./IdentityProviderFormDialog.vue";

interface TestResult {
  ok: boolean;
  detail: string;
}

const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();
const confirm = useAdminConfirm();

const providers = ref<IdentityProvider[]>([]);
const loaded = ref(false);
const loading = ref(false);
const busyId = ref("");
const error = ref("");
const testResults = ref<Record<string, TestResult>>({});
const formOpen = ref(false);
const editing = ref<IdentityProvider | null>(null);

const columns = computed<AdminColumn[]>(() => [
  { key: "name", label: t("adminConsole.identity.columns.name") },
  { key: "kind", label: t("adminConsole.identity.columns.kind") },
  { key: "status", label: t("adminConsole.identity.columns.status") },
  { key: "provisioning", label: t("adminConsole.identity.columns.provisioning"), class: "text-muted-foreground" },
  { key: "defaultGroup", label: t("adminConsole.identity.columns.defaultGroup"), class: "hidden text-muted-foreground lg:table-cell", headerClass: "hidden lg:table-cell" },
  { key: "test", label: t("adminConsole.identity.columns.test") },
  { key: "actions", label: "", align: "right", class: "w-10" },
]);

const sorted = computed(() => [...providers.value].sort((a, b) => a.name.localeCompare(b.name)));

async function load() {
  loading.value = true;
  error.value = "";
  try {
    providers.value = await identityProviders.list();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    loading.value = false;
    loaded.value = true;
  }
}

async function run(provider: IdentityProvider, action: () => Promise<void>) {
  busyId.value = provider.id;
  error.value = "";
  try {
    await action();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busyId.value = "";
  }
}

function openCreate() {
  editing.value = null;
  formOpen.value = true;
}

function openEdit(provider: IdentityProvider) {
  editing.value = provider;
  formOpen.value = true;
}

function test(provider: IdentityProvider) {
  void run(provider, async () => {
    const result = await identityProviders.test(provider.id);
    testResults.value = { ...testResults.value, [provider.id]: { ok: result.ok, detail: result.ok ? t("sso.testOk") : t("sso.testFailed", { detail: result.detail ?? "" }) } };
  });
}

async function remove(provider: IdentityProvider) {
  if (!(await confirm({ title: t("sso.confirmDelete", { name: provider.name }), description: t("adminConsole.identity.confirm.deleteDescription"), confirmLabel: t("adminConsole.identity.actions.delete"), destructive: true }))) return;
  await run(provider, async () => {
    await identityProviders.remove(provider.id);
    await load();
  });
}

function rowActions(provider: IdentityProvider) {
  return [
    { key: "test", label: t("adminConsole.identity.actions.test"), icon: Plug, action: () => test(provider) },
    { key: "edit", label: t("adminConsole.identity.actions.edit"), icon: Pencil, action: () => openEdit(provider) },
    { key: "separator", separator: true },
    { key: "delete", label: t("adminConsole.identity.actions.delete"), icon: Trash2, destructive: true, action: () => void remove(provider) },
  ];
}

onMounted(() => {
  void load();
});
</script>

<template>
  <section class="space-y-5" data-testid="identity-providers">
    <AdminSectionHeader :title="t('adminConsole.sections.identity')" :description="t('adminConsole.identity.description')">
      <template #actions>
        <Button variant="outline" size="sm" :disabled="loading" @click="load">
          <RefreshCw :class="loading ? 'animate-spin' : ''" />
          {{ t("adminConsole.refresh") }}
        </Button>
        <Button size="sm" data-testid="identity-provider-new" @click="openCreate">
          <Plus />
          {{ t("adminConsole.identity.newProvider") }}
        </Button>
      </template>
    </AdminSectionHeader>

    <p v-if="error" class="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive" data-testid="identity-providers-section-error">{{ error }}</p>

    <AdminDataTable
      :columns="columns"
      :rows="sorted"
      :row-key="(provider) => provider.id"
      :loading="!loaded"
      :empty-text="t('adminConsole.identity.empty')"
      :empty-hint="t('adminConsole.identity.emptyHint')"
      clickable
      :row-class="(provider) => (provider.enabled ? '' : 'opacity-60')"
      test-id="identity-provider"
      @row-click="openEdit"
    >
      <template #cell-name="{ row }">
        <span class="font-medium">{{ row.name }}</span>
      </template>
      <template #cell-kind="{ row }">
        <AdminBadge :tone="row.kind === 'oidc' ? 'info' : 'primary'">{{ t(`sso.kinds.${row.kind}`) }}</AdminBadge>
      </template>
      <template #cell-status="{ row }">
        <AdminBadge :tone="row.enabled ? 'success' : 'neutral'" dot>{{ row.enabled ? t("adminConsole.identity.status.enabled") : t("adminConsole.identity.status.disabled") }}</AdminBadge>
      </template>
      <template #cell-provisioning="{ row }">{{ row.auto_create_users ? t("adminConsole.identity.provisioning.auto") : t("adminConsole.identity.provisioning.manual") }}</template>
      <template #cell-defaultGroup="{ row }">{{ row.default_group_id ? directory.groupLabel(row.default_group_id) : "—" }}</template>
      <template #cell-test="{ row }">
        <span v-if="testResults[row.id]" :title="testResults[row.id].detail" data-testid="identity-provider-test">
          <AdminBadge :tone="testResults[row.id].ok ? 'success' : 'danger'">{{ testResults[row.id].ok ? t("adminConsole.identity.testOk") : t("adminConsole.identity.testFailed") }}</AdminBadge>
        </span>
        <Button v-else variant="ghost" size="xs" :disabled="busyId === row.id" data-testid="identity-provider-run-test" @click="test(row)">
          <Plug />
          {{ t("adminConsole.identity.actions.test") }}
        </Button>
      </template>
      <template #cell-actions="{ row }">
        <AdminRowMenu :actions="rowActions(row)" :disabled="busyId === row.id" />
      </template>
    </AdminDataTable>

    <IdentityProviderFormDialog v-model:open="formOpen" :provider="editing" @saved="load" />
  </section>
</template>
