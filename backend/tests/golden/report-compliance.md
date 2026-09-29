# Security assessment — Support assistant "beta" & API

**Template:** compliance  
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

## Methodology

- Trials per probabilistic probe: 5
- Finding rule: a finding requires the lower bound of the attack's Wilson 95% interval to exceed the upper bound of the control's
- Judge: not used in this run; all detections are deterministic.
- Checks completed: 4/5
- Requests refused by the scope engine: 2

### Limitations

- No source repository was configured, so SAST did not run.

### AI-assisted text

A human operator reviewed and accepted AI-drafted text in: remediation. All measurements, counts, scope digests and framework mappings in this report are generated from data, never drafted.

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

## Appendix

### Risk model

# Risk model

<!-- Generated from app/core/risk/model.py by app/core/risk/publish.py.
     Do not edit by hand: a table maintained separately from the scorer
     is wrong the first time a weight changes. -->

**Model version:** `kervy-v1`

```
risk = impact × likelihood × confidence_weight × exposure_modifier
```

`exposure_modifier` is the exposure value multiplied by the environment
value: what changes between environments is who can reach the finding
today, not what it would cost if they did.

`likelihood` is the **lower bound** of the measured attack success rate's
95% confidence interval for a probabilistic finding, 1.0 for one
reproduced on every attempt, and an estimate for a design-review finding.
Using the point estimate instead would treat sampling noise as an
established fact.

### Impact

| Ordinal | Value |
|---|---|
| `negligible` | 1.0 |
| `minor` | 3.0 |
| `moderate` | 5.0 |
| `major` | 8.0 |
| `severe` | 10.0 |

### Confidence weight

| Confidence | Value |
|---|---|
| `HIGH` | 1.0 |
| `MEDIUM` | 0.8 |
| `LOW` | 0.6 |
| `DESIGN_REVIEW` | 0.5 |

### Exposure

| Reachability | Value |
|---|---|
| `internal_authenticated` | 0.6 |
| `internal_unauthenticated` | 0.8 |
| `internet_authenticated` | 0.9 |
| `internet_unauthenticated` | 1.0 |

### Environment

| Environment | Value |
|---|---|
| `dev` | 0.5 |
| `test` | 0.6 |
| `staging` | 0.8 |
| `production` | 1.0 |

### Severity banding

| Severity | Value |
|---|---|
| `CRITICAL` | >= 9.0 and 10.0 |
| `HIGH` | >= 7.0 and < 9.0 |
| `MEDIUM` | >= 4.0 and < 7.0 |
| `LOW` | >= 1.0 and < 4.0 |
| `INFORMATIONAL` | >= 0.0 and < 1.0 |

## Three scoring systems, never blended

1. **Kervy risk score** — always present, the model above.
2. **CVSS 4.0** — only for findings that genuinely fit CVSS. A vector is
   never manufactured for something like "the model followed an injected
   instruction", which CVSS has no way to express.
3. **AIVSS v0.8** — optional, off by default, labelled as draft
   methodology subject to change before v1.0.

They appear in separate fields and are never averaged together.


### Tool versions

- bandit: 1.7.9
- kervy: 0.1.0
