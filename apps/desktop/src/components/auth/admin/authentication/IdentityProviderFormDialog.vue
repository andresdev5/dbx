<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Loader2 } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { useAdminDirectory } from "@/lib/auth/adminDirectory";
import { identityProviders, oidcCallbackUrl, type IdentityProvider, type IdentityProviderKind } from "@/lib/auth/identityProviders";
import { checkboxClass, fieldLabelClass, selectClass, useAdminText } from "../shared/adminUi";

type FieldKind = "text" | "select" | "checkbox";
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

const props = defineProps<{ open: boolean; provider?: IdentityProvider | null }>();
const emit = defineEmits<{ "update:open": [open: boolean]; saved: [provider: IdentityProvider] }>();
const { t } = useI18n();
const { errorText } = useAdminText();
const directory = useAdminDirectory();

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

const editing = computed(() => Boolean(props.provider));
const fields = computed(() => FIELDS[kind.value]);

function defaults(next: IdentityProviderKind): Record<string, unknown> {
  return next === "oidc" ? { redirect_uri: oidcCallbackUrl(), token_auth: "basic" } : { start_tls: false };
}

watch(
  () => props.open,
  (open) => {
    if (!open) return;
    const provider = props.provider;
    kind.value = provider?.kind ?? "oidc";
    name.value = provider?.name ?? "";
    enabled.value = provider?.enabled ?? true;
    autoCreate.value = provider?.auto_create_users ?? false;
    defaultGroup.value = provider?.default_group_id ?? "";
    config.value = { ...defaults(kind.value), ...provider?.config };
    secret.value = "";
    hasSecret.value = provider?.has_secret ?? false;
    error.value = "";
  },
  { immediate: true },
);

function changeKind(next: IdentityProviderKind) {
  if (editing.value) return;
  kind.value = next;
  config.value = defaults(next);
}

function textValue(key: string): string {
  const value = config.value[key];
  return typeof value === "string" ? value : "";
}

function setValue(key: string, value: unknown) {
  config.value = { ...config.value, [key]: value };
}

async function submit() {
  if (busy.value || !name.value.trim()) return;
  busy.value = true;
  error.value = "";
  try {
    const saved = await identityProviders.save({
      id: props.provider?.id,
      kind: kind.value,
      name: name.value.trim(),
      config: config.value,
      auto_create_users: autoCreate.value,
      default_group_id: defaultGroup.value || null,
      enabled: enabled.value,
      secret: secret.value ? secret.value : undefined,
    });
    emit("saved", saved);
    emit("update:open", false);
  } catch (e) {
    error.value = errorText(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <Dialog :open="open" @update:open="(value: boolean) => emit('update:open', value)">
    <DialogContent class="sm:max-w-2xl">
      <DialogHeader>
        <DialogTitle>{{ provider ? t("sso.editProvider", { name: provider.name }) : t("sso.newProvider") }}</DialogTitle>
      </DialogHeader>
      <form id="admin-identity-provider-form" class="max-h-[65vh] space-y-5 overflow-y-auto pr-1" data-testid="identity-provider-form" @submit.prevent="submit">
        <fieldset class="space-y-3">
          <legend class="mb-2 text-sm font-semibold">{{ t("adminConsole.identity.form.general") }}</legend>
          <div class="grid gap-3 sm:grid-cols-2">
            <label :class="['block', fieldLabelClass]">
              {{ t("sso.kind") }}
              <select :value="kind" :class="selectClass" :disabled="editing" data-testid="identity-provider-kind" @change="changeKind(($event.target as HTMLSelectElement).value as IdentityProviderKind)">
                <option v-for="item in KINDS" :key="item" :value="item">{{ t(`sso.kinds.${item}`) }}</option>
              </select>
            </label>
            <label :class="['block', fieldLabelClass]">
              {{ t("sso.name") }}
              <Input v-model="name" maxlength="80" data-testid="identity-provider-name" />
            </label>
          </div>
          <label class="flex items-center justify-between gap-3 text-sm">
            {{ t("sso.enabled") }}
            <Switch v-model="enabled" data-testid="identity-provider-enabled" />
          </label>
        </fieldset>

        <fieldset class="space-y-3 border-t border-border/70 pt-4">
          <legend class="mb-2 text-sm font-semibold">{{ t("adminConsole.identity.form.connection") }}</legend>
          <div class="grid gap-3 sm:grid-cols-2">
            <template v-for="field in fields" :key="field.key">
              <label v-if="field.kind === 'checkbox'" class="flex items-center gap-2 self-end pb-1.5 text-sm">
                <input type="checkbox" :class="checkboxClass" :checked="config[field.key] === true" :data-testid="`identity-provider-${field.key}`" @change="setValue(field.key, ($event.target as HTMLInputElement).checked)" />
                {{ t(`sso.fields.${field.key}`) }}
              </label>
              <label v-else-if="field.kind === 'select'" :class="['block', fieldLabelClass]">
                {{ t(`sso.fields.${field.key}`) }}
                <select :value="textValue(field.key)" :class="selectClass" :data-testid="`identity-provider-${field.key}`" @change="setValue(field.key, ($event.target as HTMLSelectElement).value)">
                  <option v-for="option in field.options" :key="option" :value="option">{{ t(`sso.options.${option}`) }}</option>
                </select>
              </label>
              <label v-else :class="['block', fieldLabelClass, field.key === 'redirect_uri' || field.key === 'issuer' || field.key === 'url' ? 'sm:col-span-2' : '']">
                {{ t(`sso.fields.${field.key}`) }}
                <Input :model-value="textValue(field.key)" :placeholder="field.placeholder" :data-testid="`identity-provider-${field.key}`" @update:model-value="setValue(field.key, $event)" />
              </label>
            </template>
            <label :class="['block sm:col-span-2', fieldLabelClass]">
              {{ kind === "oidc" ? t("adminConsole.identity.form.secretOidc") : t("adminConsole.identity.form.secretLdap") }}
              <Input v-model="secret" type="password" autocomplete="off" :placeholder="hasSecret ? t('sso.secretKept') : ''" data-testid="identity-provider-secret" />
            </label>
          </div>
          <p class="text-xs text-muted-foreground">{{ t(`sso.hints.${kind}`) }}</p>
        </fieldset>

        <fieldset class="space-y-3 border-t border-border/70 pt-4">
          <legend class="mb-2 text-sm font-semibold">{{ t("adminConsole.identity.form.provisioning") }}</legend>
          <label class="flex items-center gap-2 text-sm">
            <input v-model="autoCreate" type="checkbox" :class="checkboxClass" data-testid="identity-provider-auto-create" />
            {{ t("sso.autoCreate") }}
          </label>
          <label v-if="autoCreate" :class="['block', fieldLabelClass]">
            {{ t("sso.defaultGroup") }}
            <select v-model="defaultGroup" :class="selectClass" data-testid="identity-provider-default-group">
              <option value="">{{ t("sso.noGroup") }}</option>
              <option v-for="group in directory.groups.value" :key="group.id" :value="group.id">{{ group.name }}</option>
            </select>
          </label>
        </fieldset>
        <p v-if="error" class="text-sm text-destructive" data-testid="identity-providers-error">{{ error }}</p>
      </form>
      <DialogFooter>
        <Button variant="outline" @click="emit('update:open', false)">{{ t("common.cancel") }}</Button>
        <Button type="submit" form="admin-identity-provider-form" :disabled="busy || !name.trim()" data-testid="identity-provider-save">
          <Loader2 v-if="busy" class="animate-spin" />
          {{ editing ? t("adminConsole.identity.form.save") : t("adminConsole.identity.form.create") }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
