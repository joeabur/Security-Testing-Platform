# Security assessment — Support assistant "beta" & API

**Template:** executive  
**Generated:** 2026-03-04T09:30:00+00:00  
**Tool:** Kervy Security 0.1.0  
**Run:** `22222222-2222-2222-2222-222222222222`

## Executive summary

3 finding(s) were identified against Support assistant "beta" & API (llm_app, staging).

- Critical: 1
- High: 1
- Medium: 1
- Low: 0

**Not tested:** DAST, SCA, Secrets, IaC, RASP, Container, Cloud, VM, Domain, Pentest. See Framework coverage for why each did not run.

1 area(s) were **not tested** in this assessment; see Framework coverage for the list and the reasons.

## Authorization & scope

- Authorized by: A. Okafor (CISO)
- Reference: AUTH-2026-014
- Valid: 2026-03-01T00:00:00+00:00 to 2026-03-31T00:00:00+00:00
- Authorization digest: `sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- Rules of Engagement digest: `sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`
- Safe mode: on
- Excluded domains: payments.example.test
- Excluded paths: /admin

The digests above were pinned when the run started, so a later change to the authorization or the Rules of Engagement cannot alter what this report says was permitted.

## Risk summary

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| HIGH | 1 |
| MEDIUM | 1 |
| LOW | 0 |
| INFORMATIONAL | 0 |

Scores come from the Kervy risk model (`impact × likelihood × confidence_weight × exposure_modifier`). Every finding carries the inputs that produced its score, and the severity follows a published banding — see the appendix. CVSS and AIVSS, where present, are separate figures and are never averaged into this score.

## Framework coverage

### Reported against

- **cwe**: CWE-78
- **mitre_atlas**: AML.T0051
- **owasp_asvs**: V5.3.8
- **owasp_llm**: LLM01, LLM06

### Pillar coverage

| Pillar | Status | Detail |
|---|---|---|
| AI security | tested | Ran and reported against this target. |
| API security | tested | Ran and reported against this target. |
| SAST | tested | Ran and reported against this target. |
| DAST | not tested | This target is registered as 'llm_app'; the crawler and the DAST scanners run only against a target registered as 'web_app'. |
| SCA | not tested | No source repository is configured, so no dependency manifest was read. |
| Secrets | not tested | No source repository is configured. |
| IaC | not tested | No source repository is configured. |
| RASP | not tested | No runtime-protection engine exists on this platform. This target declares no runtime protection. |
| Container | not tested | This target is registered as 'llm_app'; the container engine runs only against a target registered as 'container'. |
| Cloud | not tested | This target is registered as 'llm_app'; the cloud engine runs only against a target registered as 'cloud_account'. |
| VM | not tested | This target is registered as 'llm_app'; the VM engine runs only against a target registered as 'virtual_machine'. |
| Domain | not tested | This target is registered as 'llm_app'; the domain engine runs only against a target registered as 'domain'. |
| Pentest | not tested | No pentest tools were configured or authorized for this run's Rules of Engagement (`asset_scope.pentest`). |

### Not tested

- **dependency advisories** — Advisory lookup is disabled by default (no outbound disclosure).

A category listed as reported against means at least one finding cited it. It does not mean the category was exhaustively tested.

## Remediation plan

Ordered by risk score. Effort bands are not estimated by this tool.

1. **CRITICAL** (9.1/10) — Command built from unvalidated input, with a <script> in the snippet [app/handlers.py:42]
   Pass an argument list; never shell=True.
2. **HIGH** (7.4/10) — Direct prompt injection overrides the system instruction [POST /api/chat]
   Separate instructions from data; re-assert the system policy per turn.
3. **MEDIUM** (5.0/10) — Tool invocation is not scoped to the requesting user [declared tool: create_ticket]
   Bind tool calls to the authenticated principal.
