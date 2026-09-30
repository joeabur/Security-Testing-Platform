# Acceptable use

This is authorized-testing software. Using it against a system you are not
authorized to test is, in most jurisdictions, a criminal offence — and it is
also a violation of the terms this software is provided under.

## The rule

**Only test systems you own, or systems whose owner has given you written
authorization covering the testing you are about to do.**

The platform is built so that following this rule is the path of least
resistance. A target with no authorization grant cannot be scanned; the API
returns `409`. That refusal is the product working, not an obstacle to route
around.

## What an authorization grant means here

It records a human act: a named person, in a named role, with a reference you
can trace back to a contract, statement of work or internal approval, for a
window with a start and an end. It is stored, digested onto every run, and
reproduced in every report.

It is deliberately not a checkbox. If you find yourself filling it in with
placeholder values, you are recording that nobody authorized the test, and the
report will say so to whoever reads it next.

The pentest module's exploitation tier needs a third, separate grant
(`ExploitationAuthorization`) beyond the two above — real exploit code is a
different act of authorization than a scan, and reusing a scanning grant for
it would silently broaden what its signer agreed to. See
`docs/authorization-and-scope.md`.

## Do not

- Test third-party services, SaaS products, or APIs you merely have an account
  with. An account is not authorization.
- Test a vendor's model endpoint because your application calls it. Authorize
  and test *your* application; the provider's terms govern their endpoint.
- Use the demo lab's techniques against anything other than the demo lab.
- Run with `safe_mode: false` on a production system without explicit,
  documented agreement about what state may change.
- Widen `allowed_ip_ranges` to reach internal infrastructure that the
  authorization does not cover. The engine will permit what you tell it to; the
  grant is what makes that legitimate.
- Disable, work around, or fork out the scope engine. If you need an exception,
  the answer is a narrower context, not a bypass.
- Approve your own exploitation-fire request, or arrange for a second account
  you also control to approve it. Firing a live exploit requires dual
  control — a second, different security engineer or above — and a second
  click by the same person is not a second person.

## Blackout windows and rate limits

Rules of engagement support blackout windows and request budgets. Use them. A
scan that takes a production service down during a trading window is a genuine
incident regardless of how authorized it was.

## The demo lab

`demo-target/` is intentionally vulnerable and exists to be attacked. It runs on
an internal Docker network with no gateway, publishes no ports, uses a stub
model, and refuses to start if a real AI provider credential is present in the
environment.

Do not deploy it anywhere reachable. Do not adapt it into a honeypot without
understanding that it contains deliberate authorization flaws.

## Reporting what you find

If you test a third party's system with their authorization and find something,
disclose it to them. If you find something in *this* platform, see
`SECURITY.md`.

## AI-specific

The AI probes detect using per-run random markers, not harmful content. Do not
extend them with a jailbreak corpus or harmful-content payloads, and do not
submit such a change — it will be declined (`CONTRIBUTING.md`).

Do not use the AI assistant's output as the basis for a claim in a report
without checking it. The assistant drafts; a human accepts. The platform
enforces that boundary in code, but it cannot enforce that you read what you
accept.

## Licence

Apache-2.0. The licence grants you rights to the software; it does not grant you
authorization to test anything.
