# Roles and permissions

## The ladder

```
owner  >  admin  >  security_engineer  >  analyst  >  viewer
```

Each role includes everything below it. Membership is per organization: a user
can be an owner of one and a viewer of another, and the check always resolves
against the organization in the request path.

## What each role can do

| | viewer | analyst | security engineer | admin | owner |
|---|:-:|:-:|:-:|:-:|:-:|
| Read targets, runs, findings, reports, evidence manifests | ✓ | ✓ | ✓ | ✓ | ✓ |
| Scope dry-run / `scope explain` | ✓ | ✓ | ✓ | ✓ | ✓ |
| Download an evidence bundle | | ✓ | ✓ | ✓ | ✓ |
| Change a finding's status, assign remediation | | ✓ | ✓ | ✓ | ✓ |
| List notification channels and pull-request posts | | ✓ | ✓ | ✓ | ✓ |
| Start, cancel or retest a run | | | ✓ | ✓ | ✓ |
| Publish findings to a pull request | | | ✓ | ✓ | ✓ |
| Configure a target's adapter | | | ✓ | ✓ | ✓ |
| Create a target, upload an OpenAPI spec, set RoE | | | | ✓ | ✓ |
| **Grant authorization to test a target** | | | | ✓ | ✓ |
| Manage synthetic accounts | | | | ✓ | ✓ |
| Mint or revoke API keys | | | | ✓ | ✓ |
| Manage notification channels and code-host connections | | | | ✓ | ✓ |
| Add or remove members, change roles | | | | ✓ | ✓ |
| Delete the organization | | | | | ✓ |

## The two placements worth explaining

**Granting authorization is admin, not security engineer.** It is the act the
entire platform is built around — a human taking responsibility for testing a
system. It sits with the people who are accountable for the organization, and
notably *above* the ceiling any API key can reach.

**Publishing to a pull request is security engineer, not admin.** Posting a
check run is part of running an assessment. Requiring an admin would push teams
towards putting an admin credential in CI, which is precisely the outcome the
API-key role cap exists to prevent.

## Owner is not just "top of the ladder" — it gates itself

Admin can add members, remove members, and change most roles (see the table
above), but touching the **Owner** role specifically — granting it, changing
someone away from it, or removing an owner outright — additionally requires
the caller to already be an owner. `invite_member`, `update_member_role`, and
`remove_member` (`app/api/v1/routers/organizations.py`) all check
`membership.role.at_least(Role.OWNER)` before any operation where either the
target or the requested role is `Role.OWNER`, refusing with `403` otherwise —
so an Admin, despite holding every other membership-management permission,
cannot mint a co-owner or demote one. An organization's last remaining owner
additionally cannot be demoted or removed at all — refused with `409`, not
merely discouraged — because doing so would leave the organization with no one
able to perform an owner-only action, including undoing the mistake.

## Dual control on firing a real exploit

Starting a real exploit (the pentest module's "fire" step, as opposed to the
non-destructive "simulate" step) requires two different people, both
Security Engineer or above: `POST .../runs/{run_id}/exploitation-fires`
creates the request `awaiting_approval`; a **different** caller must then
call `.../exploitation-fires/{fire_id}/approve` before it is enqueued.
`approve_fire` (`app/core/pentest/exploitation_service.py`) refuses with `409`
if the approver is the same person who requested it — the requester's own
role already clears the single-approver bar this used to ship with, so the
second check has to be a second *person*, not a second click. A third
endpoint, `.../reject`, lets the second person decline instead. This is the
one place on this platform where a role requirement alone is deliberately not
enough.

## Per-organization tool permissions, on top of the role floor

`AgentTool.enabled` and `AgentTool.minimum_role_override`
(`app/models/agent.py`) let an organization disable one of the native agent's
tools outright, or raise (never lower) the role required to use it, above the
code-defined default. `GET`/`PUT .../agent/tools/{tool_name}/config` read and
write this — reading is Analyst, writing is Admin, the same tier that
configures a notification channel or a workflow gate. `PUT` rejects an
override below the tool's own code minimum (`validate_role_override`); the
effective minimum a caller must meet is always `max(code default, org
override)`.

Both checks — enabled, and the effective minimum role — are re-evaluated by
`run_plan` (`app/core/agent/runtime.py`) on **every** step, including a step
resumed after a pause for approval: a tool disabled, or given a stricter
role, after a plan was built but before that step runs is refused there, not
silently allowed through on a stale decision made when the plan started.
Both columns existed on the `AgentTool` model since an earlier agent phase;
`minimum_role_override` in particular had no code path that ever read it
until a later whole-system review added `tool_config.py` and wired both into
`run_plan` and the new `GET`/`PUT .../agent/tools/{tool_name}/config`
endpoints. See `docs/guardrails.md` §1.4 and `docs/agent.md`.

## API key ceilings

| Scope | Acts as |
|---|---|
| `read` | viewer |
| `triage` | analyst |
| `scan` | security engineer |

The cap is applied after the membership check, so a key is always the *lower* of
its scope and the creating user's role.

## Tenant isolation

A request for a resource in an organization the caller does not belong to
returns **404**, never 403. Every query is filtered by `organization_id` at the
database level rather than by checking after loading, so a missing filter is a
missing row, not a leaked one.

`backend/tests/security/test_authorization_matrix.py` drives every route
unauthenticated (expect 401), as a non-member (expect 404), and as an
under-privileged member (expect 403), and holds a pinned route→role table. That
table exists because an earlier version of the test passed while a route was
silently downgraded from analyst to viewer; the pin makes such a change fail
with the route named.
