# Comparison with other tools

Honest positioning, including where the alternatives are better. If you are
choosing a tool, the most useful thing this page can do is tell you when not to
choose this one.

## Short version

| You want | Use |
|---|---|
| A large, maintained library of LLM attack probes, right now | **garak** |
| A research framework for building custom AI attacks | **PyRIT** |
| Prompt regression testing wired into a dev loop | **promptfoo** |
| Fast red-teaming of an LLM app with good defaults | **DeepTeam** |
| Repository and dependency scanning as a product | **Aikido**, **Snyk**, **Semgrep** |
| Classic web app DAST | **ZAP**, **Burp** |
| **Authorized-testing workflow with evidence, authorization, multi-tenancy and reports** | this |

## garak (NVIDIA)

**Better than this at:** breadth. garak has far more probes and detectors, a
larger community, and years of accumulated attack knowledge. If your question is
"what known attacks does my model fail", garak will tell you more, sooner.

**This is different at:** authorization and evidence. garak is a scanner you
point at a thing. This platform will not send a request until a named human has
recorded a grant, and every finding carries a sealed, hash-chained evidence
bundle with reproduction steps. That matters for a consultancy producing a
report someone will rely on, and is overhead if you are testing your own model
on your own laptop.

## PyRIT (Microsoft)

**Better than this at:** flexibility and multi-turn attacks. PyRIT is a
framework — orchestrators, converters, scoring — designed for researchers
building novel attack chains, including conversational ones. This platform's
probes are single or few-turn and deliberately fixed.

**This is different at:** being a product rather than a toolkit. Multi-tenancy,
RBAC, run lifecycle, findings lifecycle, retest, reports. PyRIT expects you to
write Python; this expects you to configure a target.

## promptfoo

**Better than this at:** the developer loop. promptfoo is excellent as a test
harness you run on every commit against prompt changes, with good local
ergonomics and fast feedback.

**This is different at:** the security-assessment framing. promptfoo answers "did
my prompt regress"; this answers "what is the measured attack success rate
against this deployed application, with what confidence, and what is the
evidence". Different questions.

## DeepTeam

**Better than this at:** time to first result. DeepTeam's defaults get you
red-teaming quickly with less configuration.

**This is different at:** the statistical discipline. Findings here require the
attack's confidence-interval lower bound to exceed the control's upper bound —
which means this platform reports *less*, and says so.

## Aikido, Snyk, Semgrep (as products)

**Better than this at:** almost everything in the AppSec lane. Curated rules,
maintained vulnerability databases, reachability analysis, IDE and PR
integrations, and a support contract. Their SCA data is better than ours,
because maintaining an advisory database is a full-time operation and ours is
delegated to pip-audit and Trivy.

**This is different at:** the AI engine and the authorization model. The
supply-chain and container engines here exist so an AI security assessment does
not have a hole where dependency risk should be — not because they compete with
a dedicated product.

**Choose them if** repository and dependency scanning is your main need. Choose
this if you need AI and API security testing with an authorization boundary and
evidence, and want basic AppSec coverage alongside it.

## ZAP / Burp Suite

**Better than this at:** web application testing. Session handling, an
interception proxy, and two decades of refinement in active scanning. This
platform has a crawler (Phase 15, `docs/dast.md`), but it is scope-gated and
narrow — it runs only for `kind: web_app`, and it hands the crawled URLs to
Nuclei and ZAP rather than doing its own active scanning. No browser: nothing
here executes JavaScript or renders a page.

**This is different at:** working from an OpenAPI document against APIs and
LLM applications, with a scope engine that refuses out-of-scope requests rather
than trusting the operator's configuration — including checking a discovered
URL against that scope engine *before* it is queued for the crawler, not only
before it is fetched.

## Where this platform is genuinely distinctive

1. **Authorization is a first-class object**, not a checkbox — recorded,
   digested onto every run, reproduced in every report.
2. **One outbound control point**, with DNS re-resolved at send time and no flag
   to disable it.
3. **Measured AI findings**, with Wilson intervals and a control arm, rather
   than "the model said something bad once".
4. **Evidence redacted before it is written**, content-addressed and
   hash-chained, with verification that re-hashes the files.
5. **Coverage honesty as a feature** — untested categories are named in every
   report rather than being absent from it.
6. **No invented identifiers**, enforced by shape verification.

## Where it is genuinely behind

- No browser, and the DAST adapters (Phase 15) are not scope-gated at the
  socket — Nuclei and ZAP open their own connections once handed a target
  URL (`docs/security-review.md`).
- Fewer AI probes than garak.
- No maintained vulnerability database of its own.
- No reachability analysis.
- The read-only ops dashboard (`/app`, Phase 17) has no write actions —
  starting a run, changing a finding's status, everything else that writes
  is API or CLI only there (`docs/dashboard.md`). The Next.js frontend is
  the full product UI and does write through the API.
- `docker compose up --build` is unverified.
- Pre-1.0, with no support contract behind it.

## Using them together

These are not mutually exclusive. A reasonable arrangement: garak or PyRIT for
breadth of AI attack research, a dedicated AppSec product for dependency
scanning at scale, and this platform for the engagement itself — the
authorization record, the measured findings, the evidence and the report. The
SARIF export exists so findings from elsewhere can land in the same place.
