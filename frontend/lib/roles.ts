import type { Role } from "./types";

// Mirrors Role.seniority_order in app/models/organization.py — used only to
// decide which controls a page shows; the backend re-checks every one of
// these rules itself on each write, so a stale or tampered value here can
// make a button disappear, never grant an action it wouldn't already allow.
export const ROLE_SENIORITY: Record<Role, number> = {
  viewer: 0,
  analyst: 1,
  security_engineer: 2,
  admin: 3,
  owner: 4,
};

export function atLeast(role: Role, minimum: Role): boolean {
  return ROLE_SENIORITY[role] >= ROLE_SENIORITY[minimum];
}
