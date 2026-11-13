import { coreEn, coreEs, coreZhCN } from "./core";
import { usersEn, usersEs, usersZhCN } from "./users";
import { groupsEn, groupsEs, groupsZhCN } from "./groups";
import { rolesEn, rolesEs, rolesZhCN } from "./roles";
import { grantsEn, grantsEs, grantsZhCN } from "./grants";
import { effectiveEn, effectiveEs, effectiveZhCN } from "./effective";
import { functionsEn, functionsEs, functionsZhCN } from "./functions";
import { sessionsEn, sessionsEs, sessionsZhCN } from "./sessions";
import { auditEn, auditEs, auditZhCN } from "./audit";
import { identityEn, identityEs, identityZhCN } from "./identity";
import { policiesEn, policiesEs, policiesZhCN } from "./policies";

export const adminConsoleEn = {
  ...coreEn,
  users: usersEn,
  groups: groupsEn,
  roles: rolesEn,
  grants: grantsEn,
  effective: effectiveEn,
  functions: functionsEn,
  sessions: sessionsEn,
  audit: auditEn,
  identity: identityEn,
  policies: policiesEn,
};

export const adminConsoleEs: typeof adminConsoleEn = {
  ...coreEs,
  users: usersEs,
  groups: groupsEs,
  roles: rolesEs,
  grants: grantsEs,
  effective: effectiveEs,
  functions: functionsEs,
  sessions: sessionsEs,
  audit: auditEs,
  identity: identityEs,
  policies: policiesEs,
};

export const adminConsoleZhCN: typeof adminConsoleEn = {
  ...coreZhCN,
  users: usersZhCN,
  groups: groupsZhCN,
  roles: rolesZhCN,
  grants: grantsZhCN,
  effective: effectiveZhCN,
  functions: functionsZhCN,
  sessions: sessionsZhCN,
  audit: auditZhCN,
  identity: identityZhCN,
  policies: policiesZhCN,
};
