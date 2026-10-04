# Deploying for free, on Oracle Cloud's Always Free tier

This is a concrete, step-by-step path from "nothing" to "this platform,
running on a real domain over HTTPS, for $0/month forever" — not a
survey of options. `docs/deployment.md` covers what matters once
something is running in production (RLS, upgrade order, evidence
storage); this doc covers the one thing it doesn't: how to actually get
a machine and put the stack on it without paying for either.

## Why Oracle Cloud, and not something else

As of 2026, this is genuinely the only option where every piece of this
stack — Postgres, Redis, the FastAPI backend, the Celery worker (the
process that actually runs scans), and the Next.js frontend — can run
for free, indefinitely, with no feature missing:

- **Render's free tier has no background workers at all.** Without a
  worker, queued runs never execute — the free tier of this app's single
  biggest competing option for "clone and deploy" convenience would be a
  read-only demo, not a working product.
- **Fly.io no longer has a free tier** — only a 2-hour/7-day trial, then
  it's paid from the first second a machine runs.
- **Vercel/Netlify** are excellent and free forever for the frontend, but
  frontend-only: no Python backend, no worker, no database.

Oracle's Always Free tier includes a real, persistent ARM VM — as of
2026, **2 OCPUs / 12GB RAM** (Ampere A1), with **no time limit**. That's
comfortably enough to run every service in `docker-compose.yml` on one
machine. The catches, stated up front rather than discovered halfway
through signup:

- **A credit or debit card is required** for identity verification.
  Staying within the Always Free limits below means you are never
  charged, but Oracle requires a card on file regardless.
- **ARM instance signup sometimes fails with "Out of Capacity"** in a
  given region — a known, common friction point, not something wrong
  with your account. Retrying, or trying a different availability
  domain within the same region, usually resolves it within a day.
- This is a real server you manage (SSH, `docker compose`, your own
  reverse proxy) — not a one-click PaaS. Budget 45–60 minutes.

## What you'll need before starting

- A credit/debit card (for Oracle's verification step only).
- A domain name you control, **or** a free subdomain from a dynamic-DNS
  provider like [DuckDNS](https://www.duckdns.org) — either works, and
  the free option is explained in Step 3. HTTPS via Let's Encrypt (Step
  5) needs *some* resolvable hostname; a bare IP address alone cannot get
  a trusted certificate.
- This repository's GitHub URL (to `git clone` on the VM).

## Step 1 — Create an Oracle Cloud account

1. Go to Oracle Cloud's sign-up page and start a new **Always Free**
   account (search "Oracle Cloud Free Tier" if the URL has moved since
   this was written — Oracle restructures their marketing pages often).
2. Fill in your details, verify your email, and enter a card for
   identity verification. Choose your **home region** carefully — once
   set, it cannot be changed without opening a support ticket, and your
   Always Free resources live in that region.
3. Wait for the "your account is ready" email. This can take anywhere
   from a couple of minutes to a few hours.

## Step 2 — Create the Always Free compute instance

1. In the OCI Console, go to **Compute → Instances → Create Instance**.
2. **Name**: anything (e.g. `kervy-prod`).
3. **Image and shape**: click "Edit" next to the shape. Choose
   **Ampere** (ARM) → **VM.Standard.A1.Flex**. Set **2 OCPUs** and
   **12 GB** memory — the current Always Free allocation. Leave the
   image as the Oracle-provided **Ubuntu** (22.04 or 24.04 — whichever
   is offered as "Always Free Eligible").
4. **Networking**: use the default VCN Oracle offers to create, and make
   sure **"Assign a public IPv4 address"** is checked.
5. **Add SSH keys**: let Oracle generate a key pair for you and
   **download the private key file** (`ssh-key-....key`) — you cannot
   retrieve it again later. `chmod 600` it locally.
6. Click **Create**. Wait for the instance to reach the **Running**
   state, then note its **public IP address** from the instance's
   detail page.
7. **Open firewall ports.** Two separate firewalls both default-deny
   here, and both need the same three ports opened:
   - **OCI Security List** (cloud firewall): on the instance's detail
     page, follow the link to its **Subnet**, then **Security Lists →
     Default Security List → Add Ingress Rules**. Add rules for
     `0.0.0.0/0`, destination ports **80** (HTTP) and **443** (HTTPS).
     Port 22 (SSH) is open by default — leave it as is.
   - **The VM's own OS firewall** (`iptables`, set up by Oracle's Ubuntu
     image) — handled in Step 3 below, once you're logged in.

   Do **not** open 5432 (Postgres) or 6379 (Redis) here. This stack binds
   both to the VM's own loopback interface only (see `docs/deployment.md`),
   so they are not reachable from outside the VM even if you did — but
   there is no reason to open them at the cloud firewall either.

## Step 3 — Connect, and install Docker

```bash
ssh -i /path/to/your-key.key ubuntu@<the-public-ip>
```

Then, on the VM:

```bash
# Open 80/443 in the VM's own firewall (separate from the Security List above)
sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
sudo netfilter-persistent save   # Ubuntu images from Oracle ship this; persists the rules across reboots

# Install Docker Engine + the Compose plugin (Docker's official repo, not Ubuntu's older packaged version)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker   # or log out and back in — picks up the new group membership

docker compose version   # confirm the plugin installed; should print a version, not an error
```

## Step 4 — Point a domain at the VM

**If you own a domain already**: in your registrar's DNS settings, add
an **A record** for the hostname you want (e.g. `kervy.yourdomain.com`)
pointing at the VM's public IP from Step 2. DNS propagation is usually
fast (minutes) but can take longer.

**If you don't want to buy one**: use a free DuckDNS subdomain instead —
go to [duckdns.org](https://www.duckdns.org), sign in (GitHub/Google/etc.),
and create a subdomain (e.g. `yourname.duckdns.org`) pointed at the same
public IP. This works identically for everything below; just use your
DuckDNS hostname wherever this guide says "your domain."

Either way, confirm it resolves before continuing:

```bash
dig +short yourname.duckdns.org   # or your real domain
# should print the VM's public IP
```

## Step 5 — Clone the repo and configure `.env`

```bash
git clone <this-repo's-URL> kervy
cd kervy
cp .env.example .env
```

Edit `.env` (`nano .env`) and change these from their development
defaults — the specific reasons for each are in `docs/configuration.md`
and `docs/deployment.md`:

```bash
# A real database password, not the published default
POSTGRES_PASSWORD=<generate one: openssl rand -base64 24>

# Match whatever you set POSTGRES_PASSWORD to above
DATABASE_URL=postgresql+asyncpg://kervy:<same-password>@postgres:5432/kervy

# A real secret — startup refuses to start with the development default
# once ENVIRONMENT=production is set below
JWT_SECRET=<generate one: python3 -c "import secrets; print(secrets.token_urlsafe(48))">
ENVIRONMENT=production

# Behind HTTPS now (Step 6 puts Caddy in front) — this is what makes the
# session cookie Secure
SESSION_COOKIE_SECURE=true

# Your domain, not localhost — this is what the browser is actually
# allowed to call the API from
CORS_ALLOWED_ORIGINS=["https://yourname.duckdns.org"]

# The frontend reaches the backend two different ways (frontend/lib/config.ts):
# server-rendered pages use the internal Docker name (leave this one as-is)
BACKEND_INTERNAL_URL=http://backend:8000/api/v1
# ...but the browser only ever knows your public domain. This one MUST be
# set correctly before the next step's `build` — Next.js bakes it into the
# browser bundle at build time, not at container start (see
# docs/deployment.md's "Configuration" section for why).
NEXT_PUBLIC_API_URL=https://yourname.duckdns.org/api/v1
```

Everything else in `.env.example` (AI provider, notification channels,
OAuth, SMTP) is genuinely optional — the platform works with all of it
left commented out, exactly as the file's own comments say.

## Step 6 — Install Caddy for automatic HTTPS

[Caddy](https://caddyserver.com) gets you a trusted Let's Encrypt
certificate with no manual certbot/nginx dance — it requests, installs,
and renews it automatically the first time it starts.

```bash
sudo apt-get update && sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt-get update && sudo apt-get install -y caddy
```

Replace `/etc/caddy/Caddyfile` with (substitute your actual domain):

```caddyfile
yourname.duckdns.org {
    # Everything under /api/* goes to the backend; everything else to the
    # Next.js frontend. This matches NEXT_PUBLIC_API_URL above exactly —
    # the browser calls https://yourname.duckdns.org/api/v1/..., Caddy
    # strips nothing, and the backend's own routes already live under
    # /api/v1 (app/core/constants.py's API_VERSION_PREFIX).
    handle /api/* {
        reverse_proxy localhost:8000
    }

    # Optional: the read-only server-rendered dashboard (docs/dashboard.md)
    handle /app/* {
        reverse_proxy localhost:8000
    }

    handle {
        reverse_proxy localhost:3000
    }
}
```

```bash
sudo systemctl reload caddy
sudo systemctl status caddy   # confirm it's running; check `sudo journalctl -u caddy` if not
```

## Step 7 — Build and start the stack

```bash
cd ~/kervy
docker compose build
docker compose up -d
docker compose ps   # everything should settle to "healthy" or "running" within a minute or two
```

`migrate` runs once and exits (0) — that's expected, not a failure; it
applies `alembic upgrade head` before `backend`/`worker`/`beat` start,
exactly as `docker-compose.yml`'s own `depends_on: service_completed_successfully`
requires.

If `frontend` or `backend` keep restarting, check their logs first:

```bash
docker compose logs -f backend
docker compose logs -f frontend
```

## Step 8 — Create your account, and optionally a platform owner

Visit `https://yourname.duckdns.org` and register through the normal UI.
That's it for a regular user — the first registered account automatically
becomes an org Owner the moment it creates its first organization
(`docs/authorization-and-scope.md`).

If you also want a **platform owner** (authority above any single
organization's own Owner — see `docs/authorization-and-scope.md`), run
this once, after that account has registered:

```bash
docker compose exec \
  -e KERVY_PLATFORM_OWNER_BOOTSTRAP_EMAIL=you@example.com \
  backend python -m scripts.bootstrap_platform_owner
```

## Step 9 — Verify it's actually working end to end

- `https://yourname.duckdns.org` loads the login page over a valid
  certificate (the padlock, not a browser warning).
- Register, create an organization, add the bundled demo lab as a target
  — [`docs/installation.md`](installation.md) walks through exactly
  this, and it's the same demo lab whether run locally or here.
- Grant authorization and rules of engagement, then start a run. If it
  reaches `completed` and produces findings, the worker is actually
  executing scans — the part that's impossible to get right on a
  background-worker-less free tier elsewhere.

## Known limitation carried over from the base image

The worker's Docker image (`Dockerfile.worker`) installs this platform's
own Python dependencies only — it does **not** bundle `semgrep`,
`bandit`, `pip-audit`, `checkov`, `gitleaks`, or `trivy`. This is an
existing, already-documented gap (`docs/deployment.md`'s "Scanner
binaries" section), not something this guide introduces: without them
on the worker's `PATH`, the corresponding AppSec engines report an
explicit `not tested` finding instead of failing silently. For full
AppSec coverage, add them to `Dockerfile.worker` yourself (most are
`pip install`-able; `gitleaks` and `trivy` are Go binaries you'd `COPY`
in from their own release tarballs) before `docker compose build` — out
of scope for "get something online," in scope for "get full coverage."

## Ongoing: updates, backups, costs

- **Updates**: `cd ~/kervy && git pull && docker compose build && docker compose up -d` — the same upgrade order `docs/deployment.md` describes (migrate, then API, then worker, then beat) happens automatically via `depends_on`.
- **Backups**: nothing is backed up by default. At minimum, periodically
  `docker compose exec postgres pg_dump -U kervy kervy | gzip > backup-$(date +%F).sql.gz`
  and copy it off the VM. `docs/deployment.md`'s "What is not provided"
  section is explicit that there's no backup tooling built in.
- **Cost**: $0/month as long as you stay inside the Always Free
  allocation (the 2 OCPU/12GB ARM instance, and normal outbound traffic
  — Oracle's Always Free tier includes a large free egress allowance).
  There is nothing in this setup that bills you automatically; Oracle
  requires an explicit upgrade to Pay As You Go before anything can
  charge your card.
