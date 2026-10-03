# Limitations

What this tool cannot detect, where its false positives cluster, and why. This
page exists because a security tool that does not state its limits invites its
users to assume it has none.

## What it does not test at all

| Not covered | Why |
|---|---|
| **Business logic abuse** | Whether a workflow can be misused in a way the spec permits is not something a generic probe can decide |
| **Client-side / browser security** | No DOM, no JavaScript execution, no XSS-in-browser verification |
| **Authentication protocol flaws** | OAuth/OIDC/SAML implementation weaknesses are not probed |
| **Infrastructure and cloud posture** | Out of scope by decision, not by omission |
| **Runtime protection (RASP)** | Extension points only; no agent ships, deliberately |
| **Model weights, training data, fine-tuning** | The platform tests deployed behaviour through the application's interface |
| **Multi-turn agentic exploitation** | Probes are single or few-turn. A long adversarial conversation is not simulated |

## Where the results are weaker than they look

**DAST runs under safe mode and is not gated at the socket.** The scope-gated
crawler and the Nuclei/ZAP adapters exist, but safe mode does not exercise
state-changing behaviour (see below), and unlike every other outbound path on
this platform, these two third-party scanners open their own connections
rather than going through the scope-gated transport — `docs/security-review.md`
names this explicitly. Treat a DAST finding as real; treat a DAST *clean
result* as "nothing state-changing was tried", not as "nothing is wrong".

**Coverage depends entirely on configuration.** No OpenAPI document means almost
no API findings. No synthetic accounts means no BOLA or function-level
authorization testing. No adapter means no AI findings. The report's coverage
section names each gap — but a reader who skips that section will
overestimate what was checked. This is the single biggest way to misread a
report from this tool.

**Reachability is never assessed.** A vulnerable dependency being present does
not establish that the affected code path is used. Every SCA and container
finding says so explicitly.

**Static analysis inherits its tools' limits.** Semgrep, bandit, checkov and the
rest have their own blind spots and their own false positives. The platform
normalizes and verifies identifiers; it does not second-guess whether a rule was
right.

**Absence of a tool is not absence of a problem.** If trivy or gitleaks is not
installed, the engine emits `KERVY-APPSEC-000 — not tested`. That marker is easy
to skim past in a long report.

## Where false positives cluster

| Finding | Why it misfires |
|---|---|
| `KERVY-API-020` (no rate limit advertised) | Checks for rate-limit *headers*. A target that rate-limits without advertising it is reported and is a false positive |
| `KERVY-API-010` (missing security headers) | An API behind a gateway that adds headers downstream will be reported for the origin's response |
| `KERVY-API-030/031` (mass assignment, analysis mode) | Read from the declared schema, not exercised. A field the server ignores still looks bindable |
| `KERVY-SUPPLY-030` (name confusion) | Legitimate packages routinely wrap a popular name. Reported at LOW with `DESIGN_REVIEW` confidence for exactly this reason |
| `KERVY-SUPPLY-023` (unknown licence) | Depends on installed metadata. A dependency not installed in the scanning environment classifies as unknown |
| `KERVY-API-040` (invalid input causes a server error) | A 500 on malformed input is a robustness issue; whether it is a security issue depends on what leaks |

## Where false negatives cluster

- **AI probes are conservative by construction.** A finding is raised only when
  the attack's confidence-interval lower bound exceeds the control's upper
  bound. Genuine but marginal weaknesses fall below that line, deliberately —
  see `docs/detection-methodology.md`.
- **Single-shot observations are capped at MEDIUM confidence**, so a real
  vulnerability seen once is reported quietly.
- **Safe mode does not exercise state-changing behaviour.** Findings that only
  manifest on a write are reported as design review, or not at all.
- **The name-confusion engine consults no registry**, so true dependency
  confusion — a private name that also exists publicly — cannot be detected.
- **Container scanning does not read base image layers.** A vulnerable package
  present only in a base layer is not seen; the report says so.
- **The EOL table is vendored with a snapshot date.** A runtime that went
  end-of-life after that date is not flagged, and one absent from the table is
  reported as *not assessed* rather than supported.

## Things that are deliberately absent

- No exploit code, no weaponized payloads, no jailbreak corpus.
- No autofix that pushes a commit to a repository.
- No RASP agent inside a customer's production process.
- No AI-generated command execution, and no path by which the assistant can
  execute a scan, grant authorization, or change a finding's real fields.

## Scale and operational limits

- Findings are per organization, deduplicated by fingerprint. There is no
  cross-organization correlation, by design.
- A SAST finding and a DAST finding describing the same underlying defect get
  different `probe_id` prefixes and therefore different fingerprints, so they
  remain two separate findings by default. A human can link one as a
  duplicate of the other (`POST`/`DELETE .../findings/{id}/duplicate`,
  analyst or above), which excludes it from the default listing and from a
  report's own counts — but **there is no automatic cross-engine similarity
  detection**. Nothing infers the link; a finding nobody reviewed stays
  double-counted. `docs/security-review.md` has the detail on why an invented
  heuristic here was rejected as worse than the honest gap.
- No per-channel notification rate limiting: a run that promotes fifty new
  criticals sends fifty messages.
- The server-rendered dashboard at `/app` (`docs/dashboard.md`) is read-only
  — overview, findings, runs, workflows and targets — by scope decision,
  not by section missing. It has no pagination-free cap left either:
  findings and runs both page past their first 50 rows. Starting a run,
  changing a finding's status and everything else that writes is API or
  CLI only there; the dashboard shows the disabled action and the call
  that does it. This is deliberately **not** true of the Next.js frontend
  (`frontend/`), the primary product UI, which writes through the API for
  most of this already — creating/starting/cancelling a run, changing a
  finding's status, linking a duplicate, triggering a retest, granting
  exploitation authorization, generating a report. What that UI still
  lacks is enumerated precisely in `docs/competitive-gap-analysis.md`
  rather than summarized here as a blanket "read-only."
- `docker compose up --build` is written but unverified — see
  `docs/installation.md`.

## How to read a report from this tool

1. Read the **coverage section first**. It tells you what the findings *do not*
   cover.
2. Check each finding's **confidence and stability**. `DESIGN_REVIEW` means
   inferred from configuration, not demonstrated.
3. For probabilistic findings, look at the **interval**, not the rate.
4. Treat a clean result as "clean for what was configured and tested", never as
   "clean".
