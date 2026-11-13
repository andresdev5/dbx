export const identityEn = {
  description: "Let people sign in with your identity provider or corporate directory. Accounts are linked by the provider's identifier, never by username.",
  newProvider: "New provider",
  columns: {
    name: "Name",
    kind: "Type",
    status: "Status",
    provisioning: "New users",
    defaultGroup: "Default group",
    test: "Last test",
  },
  status: {
    enabled: "Enabled",
    disabled: "Disabled",
  },
  provisioning: {
    auto: "Created on first sign-in",
    manual: "Pre-created only",
  },
  empty: "No identity providers yet",
  emptyHint: "Add an OpenID Connect provider or an LDAP directory to offer single sign-on.",
  actions: {
    test: "Test connection",
    edit: "Edit",
    delete: "Delete",
  },
  confirm: {
    deleteDescription: "People who sign in through this provider will no longer be able to use it.",
  },
  testOk: "Works",
  testFailed: "Failed",
  form: {
    general: "General",
    connection: "Connection",
    provisioning: "Provisioning",
    secretOidc: "Client secret",
    secretLdap: "Service account password",
    create: "Create provider",
    save: "Save changes",
  },
};

export const identityEs: typeof identityEn = {
  description: "Permite entrar con tu proveedor de identidad o directorio corporativo. Las cuentas se vinculan por el identificador del proveedor, nunca por el nombre de usuario.",
  newProvider: "Nuevo proveedor",
  columns: {
    name: "Nombre",
    kind: "Tipo",
    status: "Estado",
    provisioning: "Usuarios nuevos",
    defaultGroup: "Grupo por defecto",
    test: "Última prueba",
  },
  status: {
    enabled: "Activado",
    disabled: "Desactivado",
  },
  provisioning: {
    auto: "Se crean en su primer acceso",
    manual: "Solo cuentas existentes",
  },
  empty: "Aún no hay proveedores de identidad",
  emptyHint: "Añade un proveedor OpenID Connect o un directorio LDAP para ofrecer inicio de sesión único.",
  actions: {
    test: "Probar la conexión",
    edit: "Editar",
    delete: "Eliminar",
  },
  confirm: {
    deleteDescription: "Quienes entran con este proveedor dejarán de poder usarlo.",
  },
  testOk: "Funciona",
  testFailed: "Falló",
  form: {
    general: "General",
    connection: "Conexión",
    provisioning: "Aprovisionamiento",
    secretOidc: "Secreto del cliente",
    secretLdap: "Contraseña de la cuenta de servicio",
    create: "Crear proveedor",
    save: "Guardar cambios",
  },
};

export const identityZhCN: typeof identityEn = {
  description: "允许通过身份提供商或企业目录登录。账户按提供商标识关联，绝不按用户名关联。",
  newProvider: "新建提供商",
  columns: {
    name: "名称",
    kind: "类型",
    status: "状态",
    provisioning: "新用户",
    defaultGroup: "默认用户组",
    test: "最近测试",
  },
  status: {
    enabled: "已启用",
    disabled: "已停用",
  },
  provisioning: {
    auto: "首次登录时创建",
    manual: "仅限已有账户",
  },
  empty: "还没有身份提供商",
  emptyHint: "添加 OpenID Connect 提供商或 LDAP 目录以提供单点登录。",
  actions: {
    test: "测试连接",
    edit: "编辑",
    delete: "删除",
  },
  confirm: {
    deleteDescription: "通过此提供商登录的用户将无法再使用它。",
  },
  testOk: "正常",
  testFailed: "失败",
  form: {
    general: "常规",
    connection: "连接",
    provisioning: "账户开通",
    secretOidc: "客户端密钥",
    secretLdap: "服务账户密码",
    create: "创建提供商",
    save: "保存更改",
  },
};
