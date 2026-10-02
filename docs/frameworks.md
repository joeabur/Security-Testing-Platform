# Framework mappings

Every finding cites the frameworks it maps to **and the edition each mapping
was made against**, with the date that edition was read. A mapping without a
version is not verifiable: "LLM01" means different things in different
editions, and MITRE ATLAS renames and retires technique IDs between calendar
releases.

## Pinned editions

Defined in `app/core/findings/frameworks.py`, which is the only place a version
string may come from.

| Key | Edition | Retrieved | Source |
|---|---|---|---|
| `owasp_llm_2026` | 2026 edition | 2026-09-17 | GenAI-Security-Project/GenAI-LLM-Top10, `2026/final/` |
| `owasp_asi_2026` | 2026 (ASI01–ASI10) | 2026-09-17 | genai.owasp.org |
| `owasp_api_2023` | 2023 | 2026-09-17 | owasp.org/API-Security/editions/2023 |
| `owasp_asvs` | 5.0.0 | 2026-09-30 | github.com/OWASP/ASVS |
| `mitre_atlas` | v2026.09 | 2026-09-17 | github.com/mitre-atlas/atlas-data |
| `mitre_attack` | Enterprise v19.2 | 2026-10-02 | github.com/mitre/cti |
| `nist_ai_rmf` | AI 100-1 (2023) | 2026-09-17 | nist.gov |
| `nist_ssdf` | SP 800-218 v1.1 | 2026-09-17 | csrc.nist.gov |

**`mitre_attack` is Enterprise ATT&CK, not ATLAS.** ATLAS is specific to attacks
against AI systems; the pentest module's engines (`app/core/pentest/engine.py`)
test conventional network infrastructure — service enumeration, default
credentials, a live-fired exploit — which is ATT&CK's domain, not ATLAS's. The
two frameworks cover disjoint findings and a finding never carries both.

**CWE is deliberately unversioned.** CWE identifiers are stable across MITRE's
releases in a way the others are not, and pinning a "CWE version" would imply a
precision that does not exist. A test asserts CWE carries no version string, so
this is a decision rather than an omission.

## How a mapping reaches a report

A probe declares framework references on its `ScanResult`
(`OWASP-API-2023:API1`, `CWE-639`). Normalization groups them by framework, and
the version for each group is looked up from the pinned table. Consequences:

- **A framework with no references is not claimed.** If a finding carries no
  ATLAS reference, ATLAS does not appear in its `mapping_versions` — a finding
  never implies it was assessed against a framework it says nothing about.
- **An unrecognised prefix goes to `other`**, not to a guessed framework. A
  mapping filed under the wrong framework is worse than one filed under none.
- **No version is invented.** A framework key with no pinned entry is reported
  without a version rather than given a plausible-looking one. That is the same
  rule as "never invent a CVE", applied to editions.

Verified in a live report: every finding from the quickstart run carries
`"owasp_api_2023": "2023 (retrieved 2026-09-17)"` beside its `owasp_api_2023`
references.

## Coverage honesty

Every report has a framework coverage section naming the categories that were
**not** tested and why — no adapter configured, no synthetic accounts, no
OpenAPI document, a missing tool. A report listing five findings and saying
nothing about coverage invites the reader to assume the rest is clean, which is
the failure this section exists to prevent.

## Updating an edition

1. Read the upstream source and update the mappings the probes declare.
2. Update the entry in `app/core/findings/frameworks.py`, including
   `retrieved`.
3. Run the suite. Golden report snapshots will diff, which is the point — an
   edition change should be visible in review.

Do **not** update the version string without re-reading the source. A pinned
version that nobody checked is worse than an old one that somebody did, because
it claims a verification that did not happen.

## What is not mapped

- **OWASP AIVSS** — v0.8 is a draft, and the spec requires any use of it to be
  clearly labelled as such. Not wired.
- **OWASP AISVS** — not wired.
- **NIST AI 800-1** — optional in the spec, not wired.

These are listed so the absence is a recorded decision rather than something a
reader discovers by searching for a mapping that is not there.
