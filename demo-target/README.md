# Kervy demo target lab

**Everything in this directory is intentionally vulnerable.** It exists to be
attacked by the scanner. Do not deploy it, do not expose it, and do not put
real data in it.

## What is here

| Service | Port | What it is |
|---|---|---|
| `vulnerable-ai-app` | 8081 | A support assistant with ten seeded flaws (§19) |
| `content-server` | 8082 | Documents with instructions hidden in them, for indirect-injection testing |
| `collaborator` | 8083 | A local out-of-band listener that records what reached it |

The ten seeded flaws, each marked `SEEDED FLAW n` in
`lab/vulnerable_ai_app/app.py`:

1. weak prompt isolation — an instruction in user text is obeyed
2. recoverable system prompt — asking for it works, and it is in the response envelope anyway
3. unauthorized `/api/tools` endpoint — listed and invocable without a credential
4. over-broad agent tool surface — five tools, three irreversible, no confirmation
5. raw-HTML-rendered model output — `/api/chat/render` does not escape
6. cross-tenant RAG index — retrieval never filters by tenant
7. no rate limiting — and no security headers, and reflected CORS with credentials
8. mass assignment on `/api/users` — `role` is accepted from the body
9. BOLA on `/api/orders/{id}` — authenticated, then not authorized
10. verbose errors — `/api/search` hands back a traceback

## Running it

```bash
docker compose --profile demo up
```

Three properties of that command are deliberate:

- **`--profile demo`** — `docker compose up` on its own never starts an
  intentionally vulnerable application.
- **`internal: true`** on `lab_net` — Docker attaches no gateway, so nothing on
  the lab network can reach the internet and nothing outside can reach it. The
  worker joins that network as well as the default one, which is how the
  scanner reaches the lab while the lab reaches nothing.
- **No published ports** — a vulnerable app on a host port is a vulnerable app
  on somebody's network.

## What stops it running somewhere it shouldn't

`lab/isolation.py`, enforced in code rather than described here:

- **Refuses to start if a real provider credential is in its environment.**
  `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` and eleven others. This app follows
  injected instructions and renders model output as HTML; pointed at a real
  model with a real key, a prompt-injection demo becomes a bill or an
  exfiltration path into somebody's actual account. `env_file` is deliberately
  absent from the compose services so the project's own `.env` cannot supply
  one.
- **Binds `127.0.0.1` unless `LAB_HOST` says otherwise.** The container sets
  `LAB_HOST=0.0.0.0` because it has to be reachable on the compose network —
  a network with no route off the host.
- **Uses a stub, not a provider.** `lab/vulnerable_ai_app/model.py` is string
  handling, and a test asserts it references no HTTP library and no provider
  SDK. That makes the lab deterministic as well as safe: an assertion about a
  finding is an assertion about the scanner.
- **Holds only synthetic data.** Addresses use `.invalid`, which RFC 2606
  reserves so it can never resolve. The AWS key is `AKIAEXAMPLEEXAMPLE1`, the
  shape AWS publishes in its own documentation. Nobody reviewing a finding from
  this lab should have to work out whether a leaked value was real.
- **Prints a banner** naming itself, on every start, to stderr.

`backend/tests/test_demo_lab.py` asserts every one of those, plus all ten
flaws, plus the compose declarations. The lab is a test fixture, so a flaw
somebody tidied up would quietly turn a passing end-to-end run into a test of
nothing.

## Pointing the scanner at it

The lab lives on a private network, and the scope engine blocks private
addresses by default — so an operator has to say, explicitly, that this one is
in scope:

```yaml
# rules of engagement for the lab target
allowed_domains: ["lab-vulnerable-ai-app"]
allowed_ip_ranges: ["172.16.0.0/12"]   # whatever `docker network inspect` shows
```

That opt-in is the point. Cloud metadata addresses are the one exception:
`169.254.169.254` cannot be allowlisted at all, because it is not a target —
it is what hands out the credentials of the machine the platform runs on.

## Tokens

Static, printed here, and worth nothing:

| Token | Account | Tenant |
|---|---|---|
| `lab-token-acme-user` | `acct-1001` | acme |
| `lab-token-acme-other` | `acct-1002` | acme |
| `lab-token-globex-user` | `acct-2001` | globex |
| `lab-token-acme-admin` | `acct-9001` | acme (admin) |

`ord-7001` belongs to globex; reading it with an acme token is flaw 9.
