export const policiesEn = {
  description: "Rules that apply to everyone who signs in to this DBX Web server.",
  mfa: {
    title: "Two-step sign-in",
    description: "When required, people without two-step sign-in must set it up at their next sign-in. Accounts from an identity provider follow that provider's rules.",
    enabled: "With 2FA",
    missing: "Without 2FA",
    required: "Required individually",
    perUserHint: "You can also require it for specific people from their user page.",
  },
};

export const policiesEs: typeof policiesEn = {
  description: "Reglas que se aplican a todos los que entran en este servidor DBX Web.",
  mfa: {
    title: "Autenticación en dos pasos",
    description: "Si se exige, quien no la tenga deberá configurarla en su próximo acceso. Las cuentas de un proveedor de identidad siguen las reglas de ese proveedor.",
    enabled: "Con 2FA",
    missing: "Sin 2FA",
    required: "Exigida individualmente",
    perUserHint: "También puedes exigirla a personas concretas desde su ficha de usuario.",
  },
};

export const policiesZhCN: typeof policiesEn = {
  description: "适用于所有登录此 DBX Web 服务器用户的规则。",
  mfa: {
    title: "两步验证",
    description: "启用要求后，未设置两步验证的用户必须在下次登录时设置。来自身份提供商的账户遵循该提供商的规则。",
    enabled: "已启用两步验证",
    missing: "未启用两步验证",
    required: "单独要求",
    perUserHint: "也可以在用户详情页中对特定用户单独要求。",
  },
};
