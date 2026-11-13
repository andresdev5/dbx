export const functionsEn = {
  description: "In strict mode, calling a function that is neither standard nor allowlisted requires EXECUTE on the database.",
  search: "Search connections",
  columns: {
    connection: "Connection",
    mode: "Mode",
    allowlist: "Allowed functions",
  },
  strict: "Strict",
  standard: "Standard",
  functionsCount: "{count} functions",
  edit: "Edit policy",
  dialogTitle: "Functions on {name}",
  empty: "No connections match this search",
};

export const functionsEs: typeof functionsEn = {
  description: "En modo estricto, llamar a una función que no sea estándar ni esté en la lista permitida requiere EXECUTE sobre la base de datos.",
  search: "Buscar conexiones",
  columns: {
    connection: "Conexión",
    mode: "Modo",
    allowlist: "Funciones permitidas",
  },
  strict: "Estricto",
  standard: "Estándar",
  functionsCount: "{count} funciones",
  edit: "Editar política",
  dialogTitle: "Funciones en {name}",
  empty: "Ninguna conexión coincide con la búsqueda",
};

export const functionsZhCN: typeof functionsEn = {
  description: "严格模式下，调用既非标准函数也不在允许列表中的函数需要数据库上的 EXECUTE 权限。",
  search: "搜索连接",
  columns: {
    connection: "连接",
    mode: "模式",
    allowlist: "允许的函数",
  },
  strict: "严格",
  standard: "标准",
  functionsCount: "{count} 个函数",
  edit: "编辑策略",
  dialogTitle: "{name} 上的函数",
  empty: "没有符合搜索的连接",
};
