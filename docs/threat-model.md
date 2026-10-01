# Threat model

What this platform is trusted with, who could abuse that trust, and what stops
them.

## What it holds

| Asset | Sensitivity |
|---|---|
| Authorization grants | Legal record of who permitted testing |
| Target credentials | **Not held** — only the names of environment variables |
| Evidence bundles | Request/response exchanges against a customer's system — the most sensitive artifact here |
| Findings and reports | An inventory of a customer's unfixed vulnerabilities |
| Audit log | The record of who did what |
| Code-host tokens, webhook URLs, SMTP passwords | **Not held** — names only |
| An org's own native-agent provider credential (`AgentProvider`) | **Not held** — only the env-var name, the same shape every other credential on this platform gets |
| OAuth identity, password reset tokens, TOTP recovery codes | Provider subject id + link-time email (not a secret); reset tokens and recovery codes are single-use, short-lived, and stored only as SHA-256 digests — see `docs/authentication.md` |

The two worst outcomes are: *this platform is used to attack something it was
not authorized to attack*, and *the inventory of a customer's vulnerabilities
leaks*.

## Adversaries

**1. A malicious or compromised organization admin.** The most realistic
insider. They can create targets and grant authorization — that is the role's
purpose. What they must not be able to do is turn the platform into a general
SSRF proxy.

*Controls:* every outbound path goes through the scope engine, which re-resolves
DNS and refuses blocked address ranges. Cloud metadata addresses are refused
unconditionally, not overridably. Notification and code-host destinations must
be sanctioned by an **operator, in the environment** — the database alone cannot
widen egress. Vendor kinds are pinned to vendor hosts in code. Within the
organization itself, an Admin cannot grant, change, or remove another
member's **Owner** role — only an existing Owner can — and an organization's
last Owner can never be demoted or removed at all, so a single compromised
Admin cannot quietly promote an accomplice above itself or strip the one role
that could undo the damage (`docs/rbac.md`). And a single compromised
Admin or Owner cannot, alone, fire a real exploit against a target: dual
control requires a second, different Security-Engineer-or-above person to
approve — the requester is refused with `409` if they try to approve their
own request (`docs/rbac.md` §"Dual control on firing a real exploit").

**2. A compromised CI credential.** An API key in a runner is the most exposed
credential issued.

*Controls:* keys are capped at *security engineer* regardless of who created
them, so a stolen key cannot create a target, grant authorization, add a member,
or mint another key. Keys are hashed, shown once, revocable, and may expire.

**3. A hostile target.** The system under test is adversarial by definition. It
can return huge bodies, redirect to internal addresses, serve malformed specs,
or embed instructions aimed at the AI layer.

*Controls:* redirects are never followed — a 3xx `Location` is re-checked as a
fresh target. Response bodies are capped. The OpenAPI parser is hardened against
hostile input. AI probe detection is marker-based, so a target cannot talk its
way to a clean result. Target output never becomes an instruction to the
assistant.

**4. A malicious plugin or third-party tool.** Plugins run in-process. **There
is no sandbox, and the documentation says so plainly.**

*Controls:* plugins load only from an operator allowlist pinned by distribution
hash, `KERVY_NO_PLUGINS=1` overrides everything, and a plugin receives a
scope-bound transport rather than a free one. A test proves a plugin cannot
bypass the scope engine. Tool output cannot introduce an unverified CVE, because
identifiers are checked for shape before they reach a finding.

**5. Another tenant.** Multi-tenant by construction.

*Controls:* every query filters by `organization_id` at the database level; a
non-member receives 404, never 403, so existence is not observable. A pinned
route→role matrix test fails by name if any route's requirement changes.

**6. Someone with read access to the database or the disk.**

*Controls:* no credential is stored — only variable names. Evidence is redacted
*before* it is written; a bundle refuses to be written if a secret survives.
Passwords are Argon2id; API keys, password reset tokens, and TOTP recovery
codes are all SHA-256 digests, never a recoverable value. Evidence is
content-addressed and hash-chained, and verification re-hashes the files, so
replacing a bundle without updating the chain is detected.

**7. The AI provider.** A third party that sees whatever is sent to it.

*Controls:* entirely optional — unset, the platform behaves identically. Calls
go through the gated transport under a context allowlisting only the provider
host. The key is held by env-var reference. The assistant cannot execute a scan,
grant authorization, or change a finding's real fields under any autonomy mode,
and an import-linter rule confirms nothing in `core` outside `assistant/`
depends on it.

**8. Someone who has phished or reused a victim's password.** The most common
real-world path in, and one this platform cannot prevent at the source — a
person choosing a weak or reused password is outside this system's control.

*Controls:* login is rate limited on both per-identity and per-IP dimensions
(`docs/rate-limiting.md`), so a guessed or list-based attack costs time and
shows up in the audit log long before it succeeds. Two-factor authentication
is available per-user (off by default, on request): with it enabled, a
correct password alone returns a short-lived challenge, not a session, and
the second step has its own, tighter rate-limit budget
(`docs/authentication.md`). If a password is suspected to have leaked,
`/auth/logout-all` or a password reset both immediately invalidate every
outstanding session, not merely the one the attacker or the victim happens
to be holding (`docs/revocation.md`).

## Trust boundaries

```
  operator (environment)  ──  can sanction new outbound destinations
        │                     can disable plugins entirely
        ▼
  organization admin      ──  can grant authorization, create targets
        │                     cannot add a new destination host
        ▼
  security engineer       ──  can run scans, publish to a pull request
        │                     cannot grant authorization  ← API key ceiling
        ▼
  analyst / viewer        ──  triage and read
```

The line that matters most is between operator and admin. An admin is trusted
with a lot; they are not trusted to choose *where the platform may send data*.

## Residual risks

Stated rather than hidden; the full list with verification notes is in
`docs/security-review.md`.

- **Plugins are not sandboxed.** An allowlisted plugin runs with the worker's
  privileges. The allowlist is the control.
- **SMTP is adjudicated but not carried by the gated transport.** The scope
  engine clears the relay host; it does not see the socket. `smtplib` is pinned
  statically to one module.
- **The audit log is append-only by construction, not by database grant.** The
  service has no update or delete path; revoking `UPDATE`/`DELETE` at the
  database level is recommended in `docs/configuration.md` and not yet enforced.
- **Evidence is stored unencrypted at rest under `EVIDENCE_ROOT` by
  default**, relying on filesystem permissions and whatever the deployment
  provides. `KERVY_EVIDENCE_ENCRYPTION_KEY` (`docs/configuration.md`) turns
  on AES-256-GCM encryption for bundles written after it is set; it is
  opt-in, with one static key and no rotation, not a default or a general
  key-management solution.
- **`docker compose up --build` is unverified** in this environment.
- **The rest of the API sits behind one coarse ceiling, not a tight
  per-route budget.** `api_default` (`docs/rate-limiting.md`) bounds a
  scripted loop across every route beyond login/register/2FA/
  forgot-password/the OAuth callback, generously enough that it is not
  tuned to any one endpoint's own risk — a valid credential performing
  ordinary, human-paced use is never close to it.
