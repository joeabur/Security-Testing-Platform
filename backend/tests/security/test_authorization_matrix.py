"""The authorization pass, run against the platform itself
(docs/BUILD_SPEC.md §17.2, §24, §26 Phase 12).

§24 lists these as release-blocking: an unauthorized user is BLOCKED, and the
wrong organization is BLOCKED. This module asserts them exhaustively rather
than on a sample, by walking the real route table:

* every organization-scoped route **declares** a minimum role — a new endpoint
  cannot be added without one, because the test enumerates routes rather than
  reading a list somebody has to remember to update;
* every one of them answers **401** with no credential;
* every one answers **404** to a member of a different organization — not 403,
  because 403 would confirm the organization exists to a caller with no
  legitimate reason to know;
* every one answers **403** to a member whose role is below what it declares.

The last three are driven from the same enumeration, so coverage cannot drift
away from the routes that exist.
"""

import uuid
from typing import Any

import pytest
from fastapi.routing import APIRoute
from httpx import AsyncClient

from app.api.v1.routers import (
    api_keys,
    assistant,
    findings,
    integrations,
    organizations,
    remediation,
    reports,
    repositories,
    runs,
    surface,
    targets,
    vcs,
    workflows,
)
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.models.organization import Role

PREFIX = "/api/v1"

# Routers whose routes are organization-scoped. `auth` and `health` are
# deliberately absent: they have no organization in their path, which is the
# property the enumeration below filters on anyway.
ROUTERS = (
    api_keys,
    assistant,
    findings,
    integrations,
    organizations,
    remediation,
    reports,
    repositories,
    runs,
    surface,
    targets,
    vcs,
    workflows,
)

# Routes excluded from the live request matrix, with the reason each one
# cannot be driven the same way. Nothing is excluded from the *declaration*
# check — every route must still state a minimum role.
_NOT_LIVE_TESTED = {
    # Server-sent events: the handler streams until the run finishes or the
    # client goes away, so a plain request would hang the test rather than
    # return a status. Its authorization is asserted in `tests/test_runs_api.py`
    # against a real run.
    ("GET", "/organizations/{organization_id}/runs/{run_id}/stream"),
}


def _routes() -> list[tuple[str, str, Role]]:
    """Every organization-scoped route, with the role it declares."""
    found: list[tuple[str, str, Role]] = []
    for module in ROUTERS:
        for route in module.router.routes:
            if not isinstance(route, APIRoute):
                continue
            if "{organization_id}" not in route.path:
                continue
            role = _declared_role(route)
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                found.append((method, route.path, role))
    return sorted(found)


def _declared_role(route: APIRoute) -> Role:
    for dependency in route.dependant.dependencies:
        role = getattr(dependency.call, "minimum_role", None)
        if isinstance(role, Role):
            return role
    raise AssertionError(
        f"{sorted(route.methods)} {route.path} is organization-scoped but declares no "
        "membership requirement. Every such route must depend on "
        "require_membership(...): an endpoint without one is reachable by any "
        "authenticated user in any organization."
    )


def _url(path: str, organization_id: str) -> str:
    """Fill the path template with syntactically valid, non-existent ids.

    The ids do not need to exist. Authorization is decided before the handler
    looks anything up, which is the property being asserted: a caller who is
    not a member must not be able to tell whether a resource exists.
    """
    filled = path.replace("{organization_id}", organization_id)
    while "{" in filled:
        start = filled.index("{")
        end = filled.index("}", start)
        name = filled[start + 1 : end]
        placeholder = "sha256:" + "a" * 64 if "digest" in name else str(uuid.uuid4())
        filled = filled[:start] + placeholder + filled[end + 1 :]
    return PREFIX + filled


async def _register(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    anon = await client.get("/api/v1/auth/csrf")
    anon_token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": email.split("@")[0], "password": password},
        headers={HEADER_NAME: anon_token},
    )
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _organization(client: AsyncClient, headers: dict[str, str], name: str) -> str:
    response = await client.post("/api/v1/organizations", json={"name": name}, headers=headers)
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def _call(client: AsyncClient, method: str, url: str, headers: dict[str, str] | None) -> Any:
    return await client.request(method, url, headers=headers or {}, json={})


# The role every organization-scoped route requires today, pinned.
#
# The matrix below proves a route *enforces what it declares*. It cannot know
# what a route *should* declare — which is a real gap: silently relaxing
# `POST /findings/{id}/status` from analyst to viewer passes every other test
# in this file, because the weakened route then correctly enforces its weaker
# requirement. This table closes it. Any route added, removed, or changed has
# to be changed here too, deliberately, where a reviewer sees it.
EXPECTED_ROLES: dict[tuple[str, str], Role] = {
    ("DELETE", "/organizations/{organization_id}/targets/{target_id}/accounts/{label}"): Role.ADMIN,
    # One step above the SECURITY_ENGINEER that adding and scanning a
    # repository need: disconnecting one is reversible, but by someone who
    # can revoke access other people may be relying on, not by anyone who
    # can start a scan.
    ("DELETE", "/organizations/{organization_id}/repositories/{repository_id}"): Role.ADMIN,
    ("GET", "/organizations/{organization_id}"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/api-keys"): Role.ADMIN,
    ("GET", "/organizations/{organization_id}/assistant/runs/{run_id}/drafts"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/assistant/status"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/findings"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/findings/{finding_id}"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/members"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/remediation"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/repositories"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/repositories/{repository_id}"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/runs"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/runs/{run_id}"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/runs/{run_id}/events"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/runs/{run_id}/evidence"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/runs/{run_id}/evidence/verify"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/runs/{run_id}/evidence/{digest}"): Role.ANALYST,
    ("GET", "/organizations/{organization_id}/runs/{run_id}/report"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/runs/{run_id}/results"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/runs/{run_id}/retest-results"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/runs/{run_id}/stream"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/targets"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/targets/{target_id}"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/targets/{target_id}/accounts"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/targets/{target_id}/authorization"): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/targets/{target_id}/openapi"): Role.VIEWER,
    (
        "GET",
        "/organizations/{organization_id}/targets/{target_id}/rules-of-engagement",
    ): Role.VIEWER,
    ("GET", "/organizations/{organization_id}/targets/{target_id}/surface"): Role.VIEWER,
    (
        "PATCH",
        "/organizations/{organization_id}/targets/{target_id}/surface/{endpoint_id}",
    ): Role.SECURITY_ENGINEER,
    ("POST", "/organizations/{organization_id}/api-keys"): Role.ADMIN,
    ("POST", "/organizations/{organization_id}/api-keys/{key_id}/revoke"): Role.ADMIN,
    (
        "POST",
        "/organizations/{organization_id}/assistant/drafts/{draft_id}/accept",
    ): Role.SECURITY_ENGINEER,
    ("POST", "/organizations/{organization_id}/assistant/runs/{run_id}/drafts"): Role.ANALYST,
    ("POST", "/organizations/{organization_id}/findings/{finding_id}/status"): Role.ANALYST,
    ("POST", "/organizations/{organization_id}/members"): Role.ADMIN,
    # The whole point of this endpoint: security-engineer, not the admin
    # `POST /targets` needs, because adding a repository carries its own
    # self-affirmed consent instead of an operator-granted authorization.
    ("POST", "/organizations/{organization_id}/repositories"): Role.SECURITY_ENGINEER,
    (
        "POST",
        "/organizations/{organization_id}/repositories/{repository_id}/scan",
    ): Role.SECURITY_ENGINEER,
    ("POST", "/organizations/{organization_id}/retests"): Role.SECURITY_ENGINEER,
    ("POST", "/organizations/{organization_id}/runs"): Role.SECURITY_ENGINEER,
    ("POST", "/organizations/{organization_id}/runs/{run_id}/cancel"): Role.SECURITY_ENGINEER,
    ("POST", "/organizations/{organization_id}/targets"): Role.ADMIN,
    ("POST", "/organizations/{organization_id}/targets/{target_id}/authorization"): Role.ADMIN,
    ("POST", "/organizations/{organization_id}/targets/{target_id}/scope/explain"): Role.VIEWER,
    # Declaring runtime protection changes how this target's findings read: an
    # injection that succeeds against a target claiming a prompt firewall is a
    # statement about that firewall. Admin, like the other target declarations.
    (
        "PUT",
        "/organizations/{organization_id}/targets/{target_id}/runtime-protection",
    ): Role.ADMIN,
    # Phase 17 workflows. Defining one changes what gates a release, so that is
    # admin; triggering one runs an assessment, so it is the same security
    # engineer that POST /runs requires — a workflow must not be a cheaper way
    # to start a scan.
    ("POST", "/organizations/{organization_id}/workflows"): Role.ADMIN,
    ("GET", "/organizations/{organization_id}/workflows"): Role.ANALYST,
    ("GET", "/organizations/{organization_id}/workflows/{workflow_id}"): Role.ANALYST,
    ("PATCH", "/organizations/{organization_id}/workflows/{workflow_id}"): Role.ADMIN,
    ("DELETE", "/organizations/{organization_id}/workflows/{workflow_id}"): Role.ADMIN,
    (
        "POST",
        "/organizations/{organization_id}/workflows/{workflow_id}/runs",
    ): Role.SECURITY_ENGINEER,
    ("GET", "/organizations/{organization_id}/workflows/{workflow_id}/runs"): Role.ANALYST,
    ("DELETE", "/organizations/{organization_id}/notification-channels/{channel_id}"): Role.ADMIN,
    ("GET", "/organizations/{organization_id}/notification-channels"): Role.ANALYST,
    (
        "GET",
        "/organizations/{organization_id}/notification-channels/{channel_id}/deliveries",
    ): Role.ANALYST,
    ("PATCH", "/organizations/{organization_id}/notification-channels/{channel_id}"): Role.ADMIN,
    ("POST", "/organizations/{organization_id}/notification-channels"): Role.ADMIN,
    (
        "POST",
        "/organizations/{organization_id}/notification-channels/{channel_id}/test",
    ): Role.ADMIN,
    ("DELETE", "/organizations/{organization_id}/vcs-connections/{connection_id}"): Role.ADMIN,
    ("GET", "/organizations/{organization_id}/vcs-connections"): Role.ANALYST,
    (
        "GET",
        "/organizations/{organization_id}/vcs-connections/{connection_id}/posts",
    ): Role.ANALYST,
    ("PATCH", "/organizations/{organization_id}/vcs-connections/{connection_id}"): Role.ADMIN,
    ("POST", "/organizations/{organization_id}/vcs-connections"): Role.ADMIN,
    (
        "POST",
        "/organizations/{organization_id}/vcs-connections/{connection_id}/publish",
    ): Role.SECURITY_ENGINEER,
    ("PUT", "/organizations/{organization_id}/findings/{finding_id}/remediation"): Role.ANALYST,
    ("PUT", "/organizations/{organization_id}/targets/{target_id}/accounts/{label}"): Role.ADMIN,
    ("PUT", "/organizations/{organization_id}/targets/{target_id}/adapter"): Role.SECURITY_ENGINEER,
    ("PUT", "/organizations/{organization_id}/targets/{target_id}/code"): Role.ADMIN,
    ("PUT", "/organizations/{organization_id}/targets/{target_id}/openapi"): Role.ADMIN,
    ("PUT", "/organizations/{organization_id}/targets/{target_id}/rules-of-engagement"): Role.ADMIN,
}


# --- the declaration check ------------------------------------------------


def test_every_organization_scoped_route_declares_a_minimum_role() -> None:
    """Enumerated, not listed. A new endpoint cannot join the API without
    stating who may call it, because this walks the routes that exist."""
    routes = _routes()  # raises with the offending route if one is missing
    assert len(routes) >= 25, f"only found {len(routes)} routes; the enumeration is broken"


def test_no_routes_required_role_has_changed() -> None:
    """A privilege change has to be deliberate.

    Found by breaking it: downgrading a route from analyst to viewer passed
    every other assertion here, because the matrix checks that a route enforces
    what it declares — and a weakened route enforces its weaker declaration
    perfectly well.
    """
    actual = {(method, path): role for method, path, role in _routes()}

    added = sorted(set(actual) - set(EXPECTED_ROLES))
    removed = sorted(set(EXPECTED_ROLES) - set(actual))
    changed = sorted(
        f"{method} {path}: {EXPECTED_ROLES[(method, path)].value} -> {role.value}"
        for (method, path), role in actual.items()
        if (method, path) in EXPECTED_ROLES and EXPECTED_ROLES[(method, path)] is not role
    )

    assert not changed, f"a route's required role changed: {changed}"
    assert not added, (
        f"new organization-scoped route(s) {added}; add them to EXPECTED_ROLES "
        "with the role they should require"
    )
    assert not removed, f"route(s) {removed} disappeared; update EXPECTED_ROLES"


def test_the_route_table_covers_every_router_that_has_organization_routes() -> None:
    """Guards the list above: a router added to the API but not to `ROUTERS`
    would silently drop out of every assertion in this file."""
    from app.api.v1 import router as aggregate

    names = {module.__name__ for module in ROUTERS}
    missing = []
    for module_name in dir(aggregate):
        module = getattr(aggregate, module_name)
        router = getattr(module, "router", None)
        if router is None or not hasattr(router, "routes"):
            continue
        scoped = [
            route
            for route in router.routes
            if isinstance(route, APIRoute) and "{organization_id}" in route.path
        ]
        if scoped and module.__name__ not in names:
            missing.append(module.__name__)
    assert missing == [], f"routers with organization routes missing from ROUTERS: {missing}"


# --- the live matrix ------------------------------------------------------


@pytest.mark.parametrize(("method", "path", "role"), _routes())
async def test_an_unauthenticated_caller_is_refused(
    client: AsyncClient, strong_password: str, method: str, path: str, role: Role
) -> None:
    if (method, path) in _NOT_LIVE_TESTED:
        pytest.skip("streamed response; authorization covered in tests/test_runs_api.py")

    # The shared client keeps cookies from earlier tests in the session; a
    # request that passed on a leftover cookie would prove nothing.
    client.cookies.clear()
    response = await _call(client, method, _url(path, str(uuid.uuid4())), None)

    assert response.status_code == 401, f"{method} {path} answered {response.status_code}"


@pytest.mark.parametrize(("method", "path", "role"), _routes())
async def test_a_member_of_another_organization_gets_404_not_403(
    client: AsyncClient, strong_password: str, method: str, path: str, role: Role
) -> None:
    """§24's "wrong organization -> BLOCKED", and specifically *how* it is
    blocked: 404, so the response does not confirm that the organization
    exists to somebody with no legitimate reason to know."""
    if (method, path) in _NOT_LIVE_TESTED:
        pytest.skip("streamed response; authorization covered in tests/test_runs_api.py")

    owner = await _register(client, f"owner-{uuid.uuid4().hex[:8]}@example.test", strong_password)
    organization = await _organization(client, owner, "Owner Org")
    outsider = await _register(
        client, f"outsider-{uuid.uuid4().hex[:8]}@example.test", strong_password
    )

    response = await _call(client, method, _url(path, organization), outsider)

    assert response.status_code == 404, (
        f"{method} {path} answered {response.status_code} to a non-member; "
        "anything other than 404 tells them the organization exists"
    )


@pytest.mark.parametrize(
    ("method", "path", "role"),
    [item for item in _routes() if item[2] is not Role.VIEWER],
)
async def test_a_member_below_the_required_role_is_refused(
    client: AsyncClient, strong_password: str, method: str, path: str, role: Role
) -> None:
    """RBAC is enforced server-side on every route (§17.2). The frontend's
    role-based hiding is cosmetic, so this calls the API directly as the
    lowest role and expects 403."""
    if (method, path) in _NOT_LIVE_TESTED:
        pytest.skip("streamed response; authorization covered in tests/test_runs_api.py")

    suffix = uuid.uuid4().hex[:8]
    owner = await _register(client, f"rbacowner-{suffix}@example.test", strong_password)
    organization = await _organization(client, owner, f"RBAC Org {suffix}")

    viewer_email = f"rbacviewer-{suffix}@example.test"
    viewer = await _register(client, viewer_email, strong_password)
    invited = await client.post(
        f"/api/v1/organizations/{organization}/members",
        json={"email": viewer_email, "role": Role.VIEWER.value},
        headers=owner,
    )
    assert invited.status_code in (200, 201), invited.text

    response = await _call(client, method, _url(path, organization), viewer)

    assert response.status_code == 403, (
        f"{method} {path} declares {role.value} but answered {response.status_code} to a viewer"
    )


# --- the roles that may grant authorization -------------------------------


def test_only_admins_and_owners_may_grant_an_authorization() -> None:
    """§17.2 calls this out as a deliberate, security-relevant restriction
    rather than a convenience default, so it is asserted on its own."""
    grants = [
        (method, path, role)
        for method, path, role in _routes()
        if path.endswith("/authorization") and method in {"POST", "PUT"}
    ]
    assert grants, "no authorization-granting route found"
    for method, path, role in grants:
        assert role.at_least(Role.ADMIN), (
            f"{method} {path} lets {role.value} grant an authorization record"
        )


def test_no_route_lets_an_api_key_reach_an_admin_action() -> None:
    """The cap from §17.4, checked against the route table rather than against
    one endpoint: an API key's scopes top out at security engineer, so every
    admin-or-above route is out of a key's reach by construction."""
    from app.models.api_key import ApiKeyScope, role_for_scopes

    highest = role_for_scopes([scope.value for scope in ApiKeyScope])
    admin_routes = [item for item in _routes() if item[2].at_least(Role.ADMIN)]

    assert admin_routes, "no admin-only routes found; the enumeration is broken"
    assert not highest.at_least(Role.ADMIN)
