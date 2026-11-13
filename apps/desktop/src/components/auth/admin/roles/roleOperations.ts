import type { Operation } from "@/lib/auth/accessAdmin";

export const OPERATION_GROUPS: { key: "read" | "write" | "schema" | "admin"; operations: readonly Operation[] }[] = [
  { key: "read", operations: ["SELECT", "EXPORT"] },
  { key: "write", operations: ["INSERT", "UPDATE", "DELETE", "TRUNCATE", "IMPORT"] },
  { key: "schema", operations: ["CREATE", "ALTER", "DROP"] },
  { key: "admin", operations: ["GRANT", "EXECUTE", "UNCLASSIFIED"] },
];
