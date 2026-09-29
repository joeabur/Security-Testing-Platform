"""The server-rendered dashboard (docs/BUILD_SPEC.md §26 Phase 17, §27).

§27's definition of done names two properties, and neither is the kind of thing
a screenshot proves:

* **no hardcoded dashboard values — every number is a real query**;
* **every visible action works or is disabled with a reason**.

The tests below assert both against rendered HTML, plus the three structural
properties the dashboard's safety rests on: it is read-only, it is
organization-scoped by the same gate the API uses, and it escapes what it
renders.

Each was checked by breaking the control it asserts. Those attempts are
recorded in the individual docstrings, because a test that has never failed is
a test whose teeth are unproven.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.routing import APIRoute
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.dashboard import queries
from app.core.probes.models import Category, Confidence, Severity
from app.models.assessment_run import AssessmentRun, RunStatus
from app.models.authorization import Authorization
from app.models.finding import Finding, FindingStatus, Stability
from app.web import router as web_router

LAB_HOST = "dash.example.test"
LAB_URL = f"http://{LAB_HOST}"


# --------------------------------------------------------------------------
# Structure: properties that hold without a database.
# --------------------------------------------------------------------------


def test_every_dashboard_route_is_a_get() -> None:
    """Read-only is the whole CSRF story, so it is asserted, not intended.

    Originally because this platform had no CSRF token. It has one now
    (`docs/csrf.md`), so the constraint is gone and what remains is a scope
    decision: no write handlers are built, and until they are, a non-GET route
    here would be one nothing tests.

    The test stays because the exemption it guards is still load-bearing
    elsewhere — `app/core/csrf/enforce.py` treats `GET` as safe, and that is
    only true while every dashboard route is one. Adding a write route means
    changing this test deliberately *and* giving its handler a form-field CSRF
    check, which is the right order for that change.

    Verified by adding a `@router.post("/x")` handler and watching this fail.
    """
    offenders = []
    for route in web_router.router.routes:
        if not isinstance(route, APIRoute):
            continue
        methods = set(route.methods or ())
        if methods - {"GET", "HEAD", "OPTIONS"}:
            offenders.append((sorted(methods - {"HEAD", "OPTIONS"}), route.path))
    assert offenders == [], (
        f"the dashboard must be read-only; these routes are not: {offenders}. "
        "A cookie-authenticated state-changing route is forgeable without a "
        "CSRF token, and this platform does not have one."
    )


def test_every_organization_scoped_dashboard_route_declares_a_role() -> None:
    """Same rule the API lives under, enumerated the same way.

    A page that reads an organization's findings is as sensitive as the
    endpoint that returns them as JSON, so it declares a minimum role through
    `require_membership`. Enumerating beats a list somebody has to remember.
    """
    for route in web_router.router.routes:
        if not isinstance(route, APIRoute) or "{organization_id}" not in route.path:
            continue
        roles = [
            getattr(dependency.call, "minimum_role", None)
            for dependency in route.dependant.dependencies
        ]
        assert any(role is not None for role in roles), (
            f"{route.path} is organization-scoped but declares no membership "
            "requirement; it is readable by any authenticated user."
        )


def test_templates_escape_what_they_render() -> None:
    """A findings dashboard renders attacker-influenced text.

    A probe's payload is echoed back by the target and stored on the finding.
    Rendering that unescaped would make this platform's own dashboard the
    stored-XSS sink it tests its clients for.
    """
    assert web_router.templates.env.autoescape


def test_no_template_carries_a_cdn_script_tag() -> None:
    """No third-party code is fetched onto the page where findings are read.

    HTMX is served from this application's own static directory if an operator
    vendored it, and the tag is not rendered at all if they did not. A CDN tag
    would mean an unpinned third party could run script on the findings page.
    """
    for path in web_router.TEMPLATES_DIR.rglob("*.html"):
        body = path.read_text()
        for match in re.finditer(r"<script[^>]*src=[\"']([^\"']+)", body):
            src = match.group(1)
            assert src.startswith("/app/static/"), (
                f"{path.name} loads a script from {src!r}; dashboard scripts must "
                "be served by this application, not fetched from a third party."
            )


# --------------------------------------------------------------------------
# Behaviour: against a real database and a real request.
# --------------------------------------------------------------------------


async def _setup(client: AsyncClient, password: str, suffix: str) -> tuple[str, str, str]:
    """An owner, an organization, a target, and the session cookie.

    The cookie is what the dashboard actually authenticates with, so it is what
    the tests use — a Bearer header would test a path a browser never takes.
    """
    _registered_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    registered = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"dash{suffix}@example.test",
            "full_name": "Dash Owner",
            "password": password,
        },
        headers={HEADER_NAME: _registered_anon_token},
    )
    assert registered.status_code == 201, registered.text
    cookie = registered.cookies.get("kervy_session")
    assert cookie, "register must set the session cookie the dashboard reads"
    headers = {"Authorization": f"Bearer {registered.json()['access_token']}"}

    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Dash Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Dashboard lab",
                "environment": "test",
                "kind": "llm_app",
                "base_url": LAB_URL,
            },
            headers=headers,
        )
    ).json()["id"]
    return org_id, target_id, cookie


def _finding(org_id: str, target_id: str, **overrides: object) -> Finding:
    now = datetime.now(UTC)
    values: dict[str, object] = {
        "organization_id": uuid.UUID(org_id),
        "target_id": uuid.UUID(target_id),
        "fingerprint": "sha256:" + uuid.uuid4().hex * 2,
        "title": "Prompt injection overrides the system instruction",
        "category": Category.AI_SECURITY,
        "probe_id": "ai.llm01.direct",
        "probe_version": "1.0.0",
        "surface": "/api/chat",
        "severity": Severity.CRITICAL,
        "severity_rationale": "Marker recovered in 9 of 10 trials.",
        "confidence": Confidence.HIGH,
        "stability": Stability.DETERMINISTIC,
        "risk_model": "kervy-v1",
        "risk_score": 8.7,
        "risk_inputs": {},
        "description": "d",
        "impact": "i",
        "remediation": "r",
        "reproduction": [],
        "mappings": {},
        "mapping_versions": {},
        "status": FindingStatus.NEW,
        "first_seen": now,
        "last_seen": now,
        "times_seen": 3,
    }
    values.update(overrides)
    return Finding(**values)


@pytest.mark.parametrize(
    "path",
    ["", "/findings", "/runs", "/workflows", "/targets"],
)
async def test_a_non_member_gets_404_from_every_dashboard_page(
    client: AsyncClient, strong_password: str, path: str
) -> None:
    """404, not 403 — the dashboard must not confirm an organization exists.

    This is the same rule `tests/security/test_authorization_matrix.py` holds
    the API to. A second front end that leaked existence would undo it.
    """
    _, _, outsider_cookie = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    other_org, _, _ = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.get(
        f"/app/organizations/{other_org}{path}", cookies={"kervy_session": outsider_cookie}
    )
    assert response.status_code == 404


@pytest.mark.parametrize("path", ["", "/findings", "/runs", "/workflows", "/targets"])
async def test_unauthenticated_gets_no_organization_data(client: AsyncClient, path: str) -> None:
    response = await client.get(f"/app/organizations/{uuid.uuid4()}{path}")
    assert response.status_code == 401


def _cards(html: str) -> dict[str, int]:
    """Every `.card` the overview rendered, as {label: number}.

    Read back out of the HTML rather than out of the context, because the
    context is not what an operator sees. A card whose number were a literal
    would show up here as a value that does not move.
    """
    pattern = re.compile(r'<div class="k">(?P<k>[^<]+)</div>\s*<div class="n">(?P<n>-?\d+)</div>')
    return {m.group("k").strip(): int(m.group("n")) for m in pattern.finditer(html)}


def _severity_rows(html: str) -> dict[str, int]:
    """The severity breakdown table, read back out of the rendered page."""
    pattern = re.compile(
        r'<td class="sev sev-(?P<sev>[A-Z]+)">.*?</td>\s*<td class="num">(?P<n>\d+)</td>',
        re.S,
    )
    return {m.group("sev"): int(m.group("n")) for m in pattern.finditer(html)}


async def test_every_number_on_the_overview_comes_from_a_query(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    """The §27 rule, asserted against the rendered page rather than the context.

    A hardcoded value passes a "does the page render" test perfectly well, and
    it passes a test that re-reads the query too. So this reads every number
    back **out of the HTML** and requires the whole set to equal what
    `queries.overview` returns — before and after rows change.

    The first version of this test checked the query object and the presence of
    a title. Replacing a card's value with a literal `0` did not break it. This
    version was written after that failure and fails on exactly that edit.
    """
    org_id, target_id, cookie = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    jar = {"kervy_session": cookie}
    org = uuid.UUID(org_id)

    def expected(view: queries.Overview) -> dict[str, int]:
        return {
            "Open findings": view.open_findings,
            "Targets": view.targets,
            "Runs, last 7 days": view.runs_last_7_days,
            "Workflows": view.workflows,
            "Undelivered notifications": view.undelivered_notifications,
        }

    before = await client.get(f"/app/organizations/{org_id}", cookies=jar)
    assert before.status_code == 200
    empty = await queries.overview(db_session, org)
    assert _cards(before.text) == expected(empty)
    # Established rather than assumed: the "after" comparison below is only
    # meaningful if these numbers actually change.
    assert empty.open_findings == 0
    assert "No open findings match." in before.text

    db_session.add(_finding(org_id, target_id))
    db_session.add(_finding(org_id, target_id, severity=Severity.HIGH, risk_score=6.1))
    db_session.add(
        _finding(
            org_id,
            target_id,
            severity=Severity.LOW,
            risk_score=1.0,
            status=FindingStatus.ACCEPTED_RISK,
        )
    )
    await db_session.commit()

    after = await client.get(f"/app/organizations/{org_id}", cookies=jar)
    assert after.status_code == 200
    view = await queries.overview(db_session, org)

    # Two open, one accepted-risk: the accepted one is a decision somebody made
    # and the dashboard does not keep counting it as work.
    assert view.open_findings == 2
    assert view.targets == 1
    assert _cards(after.text) == expected(view)
    assert _cards(after.text)["Open findings"] == 2
    assert _severity_rows(after.text) == {
        "CRITICAL": 1,
        "HIGH": 1,
        "MEDIUM": 0,
        "LOW": 0,
        "INFORMATIONAL": 0,
    }
    assert "Prompt injection overrides the system instruction" in after.text
    assert "No open findings match." not in after.text


async def test_a_findings_filter_narrows_what_is_listed(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    org_id, target_id, cookie = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    jar = {"kervy_session": cookie}
    db_session.add(_finding(org_id, target_id, title="Critical one"))
    db_session.add(
        _finding(org_id, target_id, title="High one", severity=Severity.HIGH, risk_score=6.0)
    )
    await db_session.commit()

    page = await client.get(f"/app/organizations/{org_id}/findings?severity=HIGH", cookies=jar)
    assert page.status_code == 200
    assert "High one" in page.text
    assert "Critical one" not in page.text


async def test_an_htmx_request_gets_the_fragment_and_a_browser_gets_the_page(
    client: AsyncClient, strong_password: str
) -> None:
    """One handler, one query, two renderings.

    A partial served by its own handler would be a second source of truth for
    the same numbers. This asserts the fragment is a strict part of the page
    rather than a parallel implementation.
    """
    org_id, _, cookie = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    jar = {"kervy_session": cookie}

    full = await client.get(f"/app/organizations/{org_id}/findings", cookies=jar)
    fragment = await client.get(
        f"/app/organizations/{org_id}/findings",
        cookies=jar,
        headers={"HX-Request": "true"},
    )
    assert full.status_code == fragment.status_code == 200
    assert "<!doctype html>" in full.text.lower()
    assert "<!doctype html>" not in fragment.text.lower()
    assert 'id="findings-table"' in fragment.text
    assert fragment.text.strip() in full.text


async def test_a_disabled_action_says_why_and_names_what_does_the_job(
    client: AsyncClient, strong_password: str
) -> None:
    """§27: every visible action works or is disabled with a reason.

    A greyed-out button with no explanation fails that as surely as one that
    silently does nothing, so this requires the reason *and* the API call that
    performs the action to be on the page next to it.

    Verified by blanking `_CSRF_REASON`: the reason assertion fails.
    """
    org_id, _, cookie = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    jar = {"kervy_session": cookie}

    page = await client.get(f"/app/organizations/{org_id}/runs", cookies=jar)
    assert page.status_code == 200
    assert "<button disabled>" in page.text
    assert "read-only" in page.text
    # The reason must be the *current* one. It previously cited the absence of
    # CSRF protection, which is no longer true — a stale reason on a disabled
    # control is a false statement in the product.
    assert "no CSRF token" not in page.text
    assert "/api/v1/organizations/{organization_id}/runs" in page.text

    # Every disabled button on the page is followed by an explanation.
    buttons = page.text.count("<button disabled>")
    reasons = page.text.count('<p class="why">')
    assert buttons > 0
    assert reasons >= buttons, (
        f"{buttons} disabled button(s) but only {reasons} explanation(s); a "
        "disabled control without a stated reason is a dead end."
    )


async def test_the_targets_page_names_what_stops_a_scan(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    """A target that cannot be scanned says so, and says why, before a run fails.

    Verified by making `blockers` always empty: the first assertion fails.
    """
    org_id, target_id, cookie = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    jar = {"kervy_session": cookie}

    page = await client.get(f"/app/organizations/{org_id}/targets", cookies=jar)
    assert page.status_code == 200
    assert "no valid authorization grant" in page.text
    assert "no rules of engagement" in page.text

    rows = await queries.targets_for(db_session, uuid.UUID(org_id))
    assert [row.authorization_state for row in rows] == ["none"]
    assert uuid.UUID(target_id) in {row.id for row in rows}


async def test_an_expired_grant_is_not_reported_as_authorized(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    """Expired and valid must not render the same.

    The window is checked per request at run time; a dashboard that showed
    "granted" for a lapsed grant would be telling an operator the opposite of
    what the orchestrator is about to do.
    """
    org_id, target_id, cookie = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    now = datetime.now(UTC)
    rows = await queries.targets_for(db_session, uuid.UUID(org_id), now=now)
    assert rows[0].authorization_state == "none"

    db_session.add(
        Authorization(
            target_id=uuid.UUID(target_id),
            authorized_by_name="A Person",
            authorized_by_role="CISO",
            authorized_by_email="ciso@example.test",
            reference="DASH-1",
            valid_from=now - timedelta(days=30),
            valid_until=now - timedelta(days=1),
            accepted_by_user_id=await _owner_id(client, cookie),
            accepted_at=now - timedelta(days=30),
        )
    )
    await db_session.commit()

    lapsed = await queries.targets_for(db_session, uuid.UUID(org_id), now=now)
    assert lapsed[0].authorization_state == "expired"
    assert "no valid authorization grant" in lapsed[0].blockers

    page = await client.get(
        f"/app/organizations/{org_id}/targets", cookies={"kervy_session": cookie}
    )
    assert "expired" in page.text
    assert ">granted<" not in page.text


async def _owner_id(client: AsyncClient, cookie: str) -> uuid.UUID:
    response = await client.get("/api/v1/auth/me", cookies={"kervy_session": cookie})
    assert response.status_code == 200, response.text
    return uuid.UUID(response.json()["id"])


async def test_the_index_lists_only_organizations_this_session_belongs_to(
    client: AsyncClient, strong_password: str
) -> None:
    mine, _, cookie = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    theirs, _, _ = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    # One membership means the index redirects straight into it rather than
    # asking a question with one answer.
    response = await client.get("/app", cookies={"kervy_session": cookie})
    assert response.status_code == 303
    assert response.headers["location"] == f"/app/organizations/{mine}"
    assert theirs not in response.headers["location"]


async def test_the_index_without_a_session_shows_sign_in_rather_than_json(
    client: AsyncClient,
) -> None:
    """A browser surface answers a browser.

    The API's 401 is unchanged — `test_unauthenticated_gets_no_organization_data`
    asserts that — but the index has something useful to say to someone who is
    not signed in, and a JSON error body is not it.
    """
    response = await client.get("/app")
    assert response.status_code == 200
    assert "Sign in" in response.text
    assert "kervy-ai login" in response.text


# --------------------------------------------------------------------------
# Pagination (docs/security-review.md's "dashboard has no pagination" gap).
# --------------------------------------------------------------------------


async def test_findings_page_two_shows_rows_the_first_page_did_not(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    """The property that distinguishes real pagination from a bigger page:
    row 51 must appear on page 2 and nowhere on page 1, and page 1 must not
    silently include it too.

    Verified by dropping `.offset(offset)` from `queries.open_findings`: page
    2 then renders the exact same 50 rows as page 1.
    """
    org_id, target_id, cookie = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    jar = {"kervy_session": cookie}

    # Worst-first order means the seeded rank controls what lands where;
    # descending risk_score from 99.0 down makes row order unambiguous.
    for rank in range(web_router.PAGE_SIZE + 1):
        db_session.add(
            _finding(
                org_id,
                target_id,
                title=f"Finding rank {rank}",
                risk_score=99.0 - rank,
            )
        )
    await db_session.commit()

    page1 = await client.get(f"/app/organizations/{org_id}/findings", cookies=jar)
    page2 = await client.get(f"/app/organizations/{org_id}/findings?page=2", cookies=jar)
    assert page1.status_code == page2.status_code == 200

    assert "Finding rank 0" in page1.text
    assert f"Finding rank {web_router.PAGE_SIZE - 1}" in page1.text
    assert f"Finding rank {web_router.PAGE_SIZE}" not in page1.text

    assert f"Finding rank {web_router.PAGE_SIZE}" in page2.text
    assert "Finding rank 0" not in page2.text

    assert "Next" in page1.text
    assert "Previous" not in page1.text
    assert "Next" not in page2.text
    assert "Previous" in page2.text


async def test_findings_pagination_preserves_the_severity_filter(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    """A "next page" link that dropped the active filter would silently widen
    the result set the operator was looking at."""
    org_id, target_id, cookie = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    jar = {"kervy_session": cookie}

    for rank in range(web_router.PAGE_SIZE + 1):
        db_session.add(
            _finding(
                org_id,
                target_id,
                title=f"High rank {rank}",
                severity=Severity.HIGH,
                risk_score=50.0 - rank,
            )
        )
    db_session.add(_finding(org_id, target_id, title="Unrelated critical"))
    await db_session.commit()

    page1 = await client.get(f"/app/organizations/{org_id}/findings?severity=HIGH", cookies=jar)
    assert "severity=HIGH" in page1.text
    assert "page=2" in page1.text

    page2 = await client.get(
        f"/app/organizations/{org_id}/findings?severity=HIGH&page=2", cookies=jar
    )
    assert page2.status_code == 200
    assert f"High rank {web_router.PAGE_SIZE}" in page2.text
    assert "Unrelated critical" not in page2.text


async def _run(org_id: str, target_id: str, **overrides: object) -> AssessmentRun:
    values: dict[str, object] = {
        "organization_id": uuid.UUID(org_id),
        "target_id": uuid.UUID(target_id),
        "status": RunStatus.COMPLETED,
        "profile": "connectivity",
    }
    values.update(overrides)
    return AssessmentRun(**values)


async def test_runs_page_two_shows_runs_the_first_page_did_not(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    org_id, target_id, cookie = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    jar = {"kervy_session": cookie}

    base = datetime.now(UTC)
    for rank in range(web_router.PAGE_SIZE + 1):
        db_session.add(
            await _run(
                org_id,
                target_id,
                # Most-recent-first order means an earlier `created_at` for a
                # higher rank puts rank 0 on page 1 and the highest rank last.
                created_at=base - timedelta(minutes=rank),
                error_message=f"run rank {rank}",
            )
        )
    await db_session.commit()

    page1 = await client.get(f"/app/organizations/{org_id}/runs", cookies=jar)
    page2 = await client.get(f"/app/organizations/{org_id}/runs?page=2", cookies=jar)
    assert page1.status_code == page2.status_code == 200

    assert "run rank 0" in page1.text
    assert f"run rank {web_router.PAGE_SIZE}" not in page1.text
    assert f"run rank {web_router.PAGE_SIZE}" in page2.text
    assert "run rank 0" not in page2.text

    assert "Older" in page1.text
    assert "Newer" not in page1.text
    assert "Older" not in page2.text
    assert "Newer" in page2.text
