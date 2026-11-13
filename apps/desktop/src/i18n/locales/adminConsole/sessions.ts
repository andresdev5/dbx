export const sessionsEn = {
  description: "Browsers signed in to DBX Web right now. Revoking a session signs it out immediately.",
  search: "Search by user, IP or browser",
  anyUser: "All users",
  userFilter: "User",
  current: "This session",
  columns: {
    user: "User",
    ip: "IP address",
    client: "Browser",
    started: "Started",
    lastSeen: "Last activity",
    expires: "Expires",
  },
  empty: "No active sessions",
  emptyHint: "Try another search or clear the filters.",
  revoke: "Revoke session",
  revokeAllFor: "Sign out {username} everywhere",
  confirm: {
    revokeDescription: "The browser using this session is signed out immediately.",
    revokeAllDescription: "Every browser where this user is signed in is signed out immediately.",
  },
};

export const sessionsEs: typeof sessionsEn = {
  description: "Navegadores con sesión iniciada en DBX Web ahora mismo. Revocar una sesión la cierra de inmediato.",
  search: "Buscar por usuario, IP o navegador",
  anyUser: "Todos los usuarios",
  userFilter: "Usuario",
  current: "Esta sesión",
  columns: {
    user: "Usuario",
    ip: "Dirección IP",
    client: "Navegador",
    started: "Iniciada",
    lastSeen: "Última actividad",
    expires: "Vence",
  },
  empty: "No hay sesiones activas",
  emptyHint: "Prueba otra búsqueda o quita los filtros.",
  revoke: "Revocar sesión",
  revokeAllFor: "Cerrar todas las sesiones de {username}",
  confirm: {
    revokeDescription: "El navegador que usa esta sesión se desconecta de inmediato.",
    revokeAllDescription: "Se cierran de inmediato todos los navegadores donde este usuario tiene sesión iniciada.",
  },
};

export const sessionsZhCN: typeof sessionsEn = {
  description: "当前已登录 DBX Web 的浏览器。撤销会话会立即将其登出。",
  search: "按用户、IP 或浏览器搜索",
  anyUser: "全部用户",
  userFilter: "用户",
  current: "当前会话",
  columns: {
    user: "用户",
    ip: "IP 地址",
    client: "浏览器",
    started: "开始时间",
    lastSeen: "最近活动",
    expires: "过期时间",
  },
  empty: "没有活动会话",
  emptyHint: "请尝试其他搜索或清除筛选条件。",
  revoke: "撤销会话",
  revokeAllFor: "登出 {username} 的所有会话",
  confirm: {
    revokeDescription: "使用此会话的浏览器将立即被登出。",
    revokeAllDescription: "该用户已登录的所有浏览器都将立即被登出。",
  },
};
