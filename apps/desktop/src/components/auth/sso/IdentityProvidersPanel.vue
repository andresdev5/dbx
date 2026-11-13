<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Pencil, Plug, Trash2 } from "@lucide/vue";
import { translateBackendError } from "@/i18n/backend-errors";
import { accessAdmin, type UserGroup } from "@/lib/auth/accessAdmin";
import { identityProviders, oidcCallbackUrl, type IdentityProvider, type IdentityProviderKind } from "@/lib/auth/identityProviders";

const { t } = useI18n();

type FieldKind = "text" | "password" | "select" | "checkbox";
interface FieldSpec {
  key: string;
  kind: FieldKind;
  options?: string[];
  placeholder?: string;
}

const KINDS: IdentityProviderKind[] = ["oidc", "ldap"];
const FIELDS: Record<IdentityProviderKind, FieldSpec[]> = {
  oidc: [
    { key: "issuer", kind: "text", placeholder: "https://id.example.com/realms/dbx" },
    { key: "client_id", kind: "text" },
    { key: "redirect_uri", kind: "text" },
    { key: "scopes", kind: "text", placeholder: "openid profile email" },
    { key: "username_claim", kind: "text", placeholder: "preferred_username" },
    { key: "token_auth", kind: "select", options: ["basic", "post"] },
  ],
  ldap: [
    { key: "url", kind: "text", placeholder: "ldaps://ldap.example.com" },
    { key: "start_tls", kind: "checkbox" },
    { key: "bind_dn", kind: "text", placeholder: "cn=dbx,ou=services,dc=example,dc=com" },
    { key: "user_base_dn", kind: "text", placeholder: "ou=people,dc=example,dc=com" },
    { key: "user_filter", kind: "text", placeholder: "(uid={username})" },
    { key: "username_attribute", kind: "text", placeholder: "uid" },
    { key: "display_name_attribute", kind: "text", placeholder: "cn" },
  ],
};

const providers = ref<IdentityProvider[]>([]);
const groups = ref<UserGroup[]>([]);
const editingId = ref("");
const kind = ref<IdentityProviderKind>("oidc");
const name = ref("");
const enabled = ref(true);
const autoCreate = ref(false);
const defaultGroup = ref("");
const config = ref<Record<string, unknown>>({});
const secret = ref("");
const hasSecret = ref(false);
const busy = ref(false);
const error = ref("");
const testResult = ref<Record<string, string>>({});

const fields = computed(() => FIELDS[kind.value]);
const editing = computed(() => providers.value.find((provider) => provider.id === editingId.value));
const selectClass = "h-9 w-full rounded-md border border-input bg-background px-2 text-sm";

function errorText(e: unknown): string {
  return translateBackendError(t, e instanceof Error ? e.message : String(e)) || t("sso.failed");
}

function defaults(next: IdentityProviderKind): Record<string, unknown> {
  return next === "oidc" ? { redirect_uri: oidcCallbackUrl(), token_auth: "basic" } : { start_tls: false };
}

function resetForm(next: IdentityProviderKind = "oidc") {
  editingId.value = "";
  kind.value = next;
  name.value = "";
  enabled.value = true;
  autoCreate.value = false;
  defaultGroup.value = "";
  config.value = defaults(next);
  secret.value = "";
  hasSecret.value = false;
}

function edit(provider: IdentityProvider) {
  editingId.value = provider.id;
  kind.value = provider.kind;
  name.value = provider.name;
  enabled.value = provider.enabled;
  autoCreate.value = provider.auto_create_users;
  defaultGroup.value = provider.default_group_id ?? "";
  config.value = { ...defaults(provider.kind), ...provider.config };
  secret.value = "";
  hasSecret.value = provider.has_secret;
}

function changeKind(next: IdentityProviderKind) {
  if (!editingId.value) resetForm(next);
}

async function load() {
  try {
    [providers.value, groups.value] = await Promise.all([identityProviders.list(), accessAdmin.groups()]);
  } catch (e) {
    error.value = errorText(e);
  }
}

async function run(action: () => Promise<void>) {
  busy.value = true;
  error.value = "";
  try {
    await action();
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}

function save() {
  void run(async () => {
    await identityProviders.save({
      id: editingId.value || undefined,
      kind: kind.value,
      name: name.value.trim(),
      config: config.value,
      auto_create_users: autoCreate.value,
      default_group_id: defaultGroup.value || null,
      enabled: enabled.value,
      secret: secret.value ? secret.value : undefined,
    });
    resetForm(kind.value);
    await load();
  });
}

function remove(provider: IdentityProvider) {
  if (!window.confirm(t("sso.confirmDelete", { name: provider.name }))) return;
  void run(async () => {
    await identityProviders.remove(provider.id);
    if (editingId.value === provider.id) resetForm();
    await load();
  });
}

function test(provider: IdentityProvider) {
  void run(async () => {
    const result = await identityProviders.test(provider.id);
    testResult.value = { ...testResult.value, [provider.id]: result.ok ? t("sso.testOk") : t("sso.testFailed", { detail: result.detail ?? "" }) };
  });
}

function textValue(key: string): string {
  const value = config.value[key];
  return typeof value === "string" ? value : "";
}

function setValue(key: string, value: unknown) {
  config.value = { ...config.value, [key]: value };
}

onMounted(() => {
  resetForm();
  void load();
});
</script>

<template>
  <div class="space-y-4" data-testid="identity-providers">
    <div class="space-y-1">
      <Label class="text-base">{{ t("sso.title") }}</Label>
      <p class="text-sm text-muted-foreground">{{ t("sso.description") }}</p>
    </div>
    <p v-if="error" class="text-sm text-destructive" data-testid="identity-providers-error">{{ error }}</p>

    <div class="overflow-hidden rounded-md border border-border/60">
      <p v-if="!providers.length" class="px-3 py-3 text-sm text-muted-foreground">{{ t("sso.empty") }}</p>
      <div v-for="provider in providers" :key="provider.id" class="border-b border-border/60 px-3 py-2 last:border-b-0" data-testid="identity-provider">
        <div class="flex items-center gap-2">
          <div class="min-w-0 flex-1">
            <p class="truncate text-sm font-medium">
              {{ provider.name }}
              <span class="text-xs font-normal text-muted-foreground">· {{ t(`sso.kinds.${provider.kind}`) }}</span>
              <span v-if="!provider.enabled" class="text-xs font-normal text-muted-foreground"> · {{ t("sso.disabled") }}</span>
            </p>
            <p v-if="testResult[provider.id]" class="truncate text-xs text-muted-foreground" data-testid="identity-provider-test">{{ testResult[provider.id] }}</p>
          </div>
          <Button variant="ghost" size="icon" class="h-8 w-8" :title="t('sso.test')" :disabled="busy" @click="test(provider)">
            <Plug class="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" class="h-8 w-8" :title="t('access.edit')" :disabled="busy" @click="edit(provider)">
            <Pencil class="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" class="h-8 w-8 text-destructive hover:text-destructive" :title="t('users.delete')" :disabled="busy" @click="remove(provider)">
            <Trash2 class="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>

    <form class="space-y-2 rounded-md border border-border/60 p-3" data-testid="identity-provider-form" @submit.prevent="save">
      <p class="text-sm font-medium">{{ editing ? t("sso.editProvider", { name: editing.name }) : t("sso.newProvider") }}</p>
      <div class="grid gap-2 sm:grid-cols-2">
        <select :value="kind" :class="selectClass" :disabled="Boolean(editingId)" :aria-label="t('sso.kind')" data-testid="identity-provider-kind" @change="changeKind(($event.target as HTMLSelectElement).value as IdentityProviderKind)">
          <option v-for="item in KINDS" :key="item" :value="item">{{ t(`sso.kinds.${item}`) }}</option>
        </select>
        <Input v-model="name" :placeholder="t('sso.name')" class="h-9" data-testid="identity-provider-name" />
      </div>
      <template v-for="field in fields" :key="field.key">
        <label v-if="field.kind === 'checkbox'" class="flex items-center gap-2 text-sm">
          <input type="checkbox" :checked="config[field.key] === true" @change="setValue(field.key, ($event.target as HTMLInputElement).checked)" />
          {{ t(`sso.fields.${field.key}`) }}
        </label>
        <label v-else-if="field.kind === 'select'" class="block space-y-1 text-xs text-muted-foreground">
          {{ t(`sso.fields.${field.key}`) }}
          <select :value="textValue(field.key)" :class="selectClass" @change="setValue(field.key, ($event.target as HTMLSelectElement).value)">
            <option v-for="option in field.options" :key="option" :value="option">{{ t(`sso.options.${option}`) }}</option>
          </select>
        </label>
        <label v-else class="block space-y-1 text-xs text-muted-foreground">
          {{ t(`sso.fields.${field.key}`) }}
          <Input :model-value="textValue(field.key)" :placeholder="field.placeholder" class="h-9" :data-testid="`identity-provider-${field.key}`" @update:model-value="setValue(field.key, $event)" />
        </label>
      </template>
      <label class="block space-y-1 text-xs text-muted-foreground">
        {{ kind === "oidc" ? t("sso.fields.client_secret") : t("sso.fields.bind_password") }}
        <Input v-model="secret" type="password" autocomplete="off" :placeholder="hasSecret ? t('sso.secretKept') : ''" class="h-9" data-testid="identity-provider-secret" />
      </label>
      <div class="grid gap-2 sm:grid-cols-2">
        <label class="flex items-center gap-2 text-sm">
          <input v-model="enabled" type="checkbox" />
          {{ t("sso.enabled") }}
        </label>
        <label class="flex items-center gap-2 text-sm">
          <input v-model="autoCreate" type="checkbox" data-testid="identity-provider-auto-create" />
          {{ t("sso.autoCreate") }}
        </label>
      </div>
      <label v-if="autoCreate" class="block space-y-1 text-xs text-muted-foreground">
        {{ t("sso.defaultGroup") }}
        <select v-model="defaultGroup" :class="selectClass">
          <option value="">{{ t("sso.noGroup") }}</option>
          <option v-for="group in groups" :key="group.id" :value="group.id">{{ group.name }}</option>
        </select>
      </label>
      <p class="text-xs text-muted-foreground">{{ t(`sso.hints.${kind}`) }}</p>
      <div class="flex justify-end gap-2">
        <Button v-if="editingId" type="button" variant="ghost" size="sm" @click="resetForm(kind)">{{ t("common.cancel") }}</Button>
        <Button type="submit" size="sm" :disabled="busy || !name.trim()" data-testid="identity-provider-save">{{ t("access.save") }}</Button>
      </div>
    </form>
  </div>
</template>
