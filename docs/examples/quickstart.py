"""The quickstart from docs/installation.md, as an executable script.

This is the script that was actually run to verify Phase 13's acceptance
criterion, kept rather than rewritten so the documentation and the thing that
proved it cannot drift apart.

    python docs/examples/quickstart.py

Expects: the API on 127.0.0.1:8400, the demo lab on 127.0.0.1:8481, and a Celery
worker with KERVY_LAB_ACME_TOKEN and KERVY_LAB_GLOBEX_TOKEN exported. Override
the two URLs with KERVY_API_URL and KERVY_LAB_URL.
"""

import os
import pathlib
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx

API = os.environ.get("KERVY_API_URL", "http://127.0.0.1:8400") + "/api/v1"
LAB = os.environ.get("KERVY_LAB_URL", "http://127.0.0.1:8481")
c = httpx.Client(base_url=API, timeout=30.0)
step = lambda n, r: print(f"{n:<34} {r.status_code}") or (r.raise_for_status() or r)

# A fresh account and organization each run, so the script is re-runnable
# against the same database rather than failing the second time with a 409.
SUFFIX = uuid.uuid4().hex[:8]

csrf = c.get("/auth/csrf")
anon_token = next(
    v for k, v in csrf.cookies.items() if k in ("__Host-kervy_csrf_anon", "kervy_csrf_anon")
)
r = c.post(
    "/auth/register",
    json={
        "email": f"you-{SUFFIX}@example.test",
        "full_name": "You",
        "password": "Correct-Horse-Battery-Staple-9",
    },
    headers={"X-CSRF-Token": anon_token},
)
step("1 register", r)
h = {"Authorization": f"Bearer {r.json()['access_token']}"}

org = step(
    "2 create organization",
    c.post("/organizations", json={"name": f"Acme {SUFFIX}"}, headers=h),
).json()["id"]
tgt = step(
    "3 register the demo lab",
    c.post(
        f"/organizations/{org}/targets",
        json={
            "name": "Demo lab",
            "environment": "test",
            "kind": "llm_app",
            "base_url": LAB,
        },
        headers=h,
    ),
).json()["id"]
base = f"/organizations/{org}/targets/{tgt}"

# A run before authorization must be refused; that refusal is the product.
pre = c.post(
    f"/organizations/{org}/runs",
    json={"target_id": tgt, "authorization_confirmed": True},
    headers=h,
)
print(f"{'4 run WITHOUT authorization':<34} {pre.status_code}  <- must not be 201")
assert pre.status_code != 201, "a run was accepted without an authorization grant"

now = datetime.now(UTC)
step(
    "5 rules of engagement",
    c.put(
        f"{base}/rules-of-engagement",
        json={
            "allowed_domains": ["127.0.0.1"],
            "excluded_domains": [],
            "allowed_ip_ranges": ["127.0.0.0/8"],
            "allowed_paths": [],
            "excluded_paths": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_headers": [],
            "safe_mode": True,
            "budgets": {
                "max_requests": 600,
                "max_concurrency": 4,
                "requests_per_second": 200.0,
                "max_tokens_sent": 200000,
                "max_tokens_received": 200000,
                "max_estimated_cost_usd": 5.0,
                "max_wall_clock_minutes": 10,
            },
        },
        headers=h,
    ),
)
step(
    "6 authorization grant",
    c.post(
        f"{base}/authorization",
        json={
            "authorized_by_name": "A Person",
            "authorized_by_role": "CISO",
            "authorized_by_email": "ciso@example.test",
            "reference": "QUICKSTART",
            "valid_from": (now - timedelta(hours=1)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
        },
        headers=h,
    ),
)
step(
    "7 adapter",
    c.put(
        f"{base}/adapter",
        json={"adapter_kind": "chat_http", "adapter_config": {"endpoint": "/api/chat"}},
        headers=h,
    ),
)

# The lab publishes its own OpenAPI document; uploading it is what gives the
# API probes a surface to test. Without it a scan finds very little.
spec = httpx.get(f"{LAB}/openapi.json", timeout=15.0).content
step(
    "8 upload the lab's OpenAPI",
    c.put(
        f"{base}/openapi",
        files={"file": ("openapi.json", spec, "application/json")},
        headers=h,
    ),
)

# Two synthetic accounts, by environment-variable NAME. `ord-7001` belongs to
# globex, so reading it with the acme token is the BOLA the lab seeds.
for label, var, owned in (
    ("acme_user", "KERVY_LAB_ACME_TOKEN", ["ord-5001"]),
    ("globex_user", "KERVY_LAB_GLOBEX_TOKEN", ["ord-7001"]),
):
    step(
        f"9 synthetic account {label}",
        c.put(
            f"{base}/accounts/{label}",
            json={
                "label": label,
                "credential_env_var": var,
                "owned_object_ids": owned,
                "is_privileged": False,
            },
            headers=h,
        ),
    )

run = step(
    "10 create run",
    c.post(
        f"/organizations/{org}/runs",
        json={"target_id": tgt, "authorization_confirmed": True, "profile": "full"},
        headers=h,
    ),
).json()["id"]

deadline = time.time() + 300
while time.time() < deadline:
    s = c.get(f"/organizations/{org}/runs/{run}", headers=h).json()["status"]
    if s in ("completed", "failed", "cancelled"):
        break
    time.sleep(3)
print(f"{'11 run status':<34} {s}")
assert s == "completed", s

res = c.get(f"/organizations/{org}/runs/{run}/results", headers=h).json()
codes = sorted({i["result_code"] for i in res})
print(f"{'12 scan results':<34} {len(res)} results, {len(codes)} distinct codes")
print("   codes:", ", ".join(codes[:14]))

fnd = c.get(f"/organizations/{org}/findings", headers=h).json()
print(f"{'13 findings':<34} {len(fnd)}")
assert fnd, "no findings"

OUT = pathlib.Path(os.environ.get("KERVY_OUT_DIR", "."))
OUT.mkdir(parents=True, exist_ok=True)
for fmt, ext in (("markdown", "md"), ("sarif", "sarif.json"), ("json", "json")):
    rp = c.get(
        f"/organizations/{org}/runs/{run}/report",
        params={"report_format": fmt},
        headers=h,
    )
    path = OUT / f"report.{ext}"
    path.write_bytes(rp.content)
    print(
        f"{'14 download report ' + fmt:<34} {rp.status_code}  {len(rp.content)} bytes -> {path}"
    )
    assert rp.status_code == 200

ev = c.get(f"/organizations/{org}/runs/{run}/evidence/verify", headers=h).json()
print(f"{'15 evidence chain verify':<34} ok={ev.get('ok')}")
print("\nQUICKSTART OK")
