"""The server-rendered dashboard (docs/BUILD_SPEC.md §26 Phase 17, §27).

Jinja2 templates and HTMX, served by the same FastAPI application as the API.
Three properties are deliberate, and each is asserted in `tests/test_web.py`
rather than left as a claim in a docstring.

**Read-only, and that is a scope decision rather than a security one now.**
CSRF protection exists (`docs/csrf.md`) and would cover a write handler here
the same way it covers the API's, so the reason no write handler is built
is simply that none has been — see `_CSRF_REASON` below, which is what a
disabled control's own explanation says, rather than leaving this docstring
to make a claim the UI itself no longer makes. Every route here is a `GET`
regardless, and a test walks the route table to prove it: a mutating route
cannot be added without that test failing. Actions that *would* change
state are rendered as disabled controls carrying the reason and the API
call that does the job — the §27 rule ("every visible action works or is
disabled with a reason") satisfied honestly rather than by hiding the
buttons.

**Every number comes from a query.** The handlers below pass nothing to a
template but what `app.web.queries` returned. §27's definition of done says
*no hardcoded dashboard values*, and a template that wanted a number not in
that module would have to add it there first.

**Organization scoping is the same gate as the API's.** Each route depends on
`require_membership(...)`, so a non-member gets the same 404 a non-member gets
from `/api/v1`, and the role a page needs is declared where a reviewer sees it.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app.auth.dependencies import DbSession, require_membership
from app.models.organization import Membership, Organization, Role
from app.models.workflow import Workflow
from app.web import queries

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
HTMX_FILE = STATIC_DIR / "htmx.min.js"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
# Resolved once, at import, and exposed to every template: the base layout
# emits the `<script>` tag only when an operator has actually vendored HTMX
# into `static/`. There is deliberately no CDN fallback — see
# `app/web/static/README.md` for why a security product does not fetch
# unpinned third-party code onto the page where findings are read.
templates.env.globals["htmx_available"] = HTMX_FILE.is_file()
# Autoescaping is on by default for `.html` in Jinja2's `select_autoescape`,
# and this asserts it rather than trusting the default: findings carry attacker
# influenced text (a probe's own payload echoed back by a target), so a
# dashboard that rendered it raw would be stored XSS in a security product.
assert templates.env.autoescape, "template autoescaping must be on"

router = APIRouter(prefix="/app", tags=["dashboard"])

#: The dashboard shows findings, runs and configuration. Viewer is the floor,
#: matching the read-only API routes for the same data.
Viewer = Annotated[Membership, Depends(require_membership(Role.VIEWER))]


def _page(
    request: Request, name: str, context: dict[str, Any], *, partial: str | None = None
) -> HTMLResponse:
    """Render a full page, or just its fragment when HTMX asked for one.

    HTMX sends `HX-Request`; when it is present the browser already has the
    surrounding page and only the fragment is sent back. Same handler, same
    query, one code path — a partial that drifted from its page would be a
    second source of truth about the same numbers.
    """
    if partial and request.headers.get("HX-Request") == "true":
        name = partial
    return templates.TemplateResponse(request, name, context)


@router.get("", response_class=HTMLResponse, response_model=None)
@router.get("/", response_class=HTMLResponse, response_model=None)
async def index(request: Request, db: DbSession) -> HTMLResponse | RedirectResponse:
    """The organizations this session can see, or a prompt to sign in.

    Unauthenticated gets the sign-in page rather than a JSON 401: this is a
    browser surface, and a 401 body would be an error page a person cannot act
    on. The API's behaviour is unchanged.
    """
    user = await _optional_user(request, db)
    if user is None:
        return templates.TemplateResponse(request, "login.html", {"user": None})

    rows = (
        await db.execute(
            select(Organization)
            .join(Membership, Membership.organization_id == Organization.id)
            .where(Membership.user_id == user.id)
            .order_by(Organization.name)
        )
    ).scalars()
    organizations = list(rows)
    if len(organizations) == 1:
        return RedirectResponse(f"/app/organizations/{organizations[0].id}", status_code=303)
    return templates.TemplateResponse(
        request, "index.html", {"user": user, "organizations": organizations}
    )


async def _optional_user(request: Request, db: DbSession) -> Any:
    """`get_current_user`, but a missing or bad credential is not an error.

    Only used by the index page, which has something useful to show either way.
    Every other route uses the real dependency, so there is no route where
    authentication is optional and data is shown.
    """
    from fastapi import HTTPException

    from app.auth.dependencies import get_current_user

    try:
        return await get_current_user(request, db)
    except HTTPException:
        return None


@router.get("/organizations/{organization_id}", response_class=HTMLResponse)
async def dashboard(
    request: Request, organization_id: uuid.UUID, db: DbSession, membership: Viewer
) -> HTMLResponse:
    return _page(
        request,
        "dashboard.html",
        {
            "membership": membership,
            "organization_id": organization_id,
            "overview": await queries.overview(db, organization_id),
            "runs": await queries.recent_runs(db, organization_id, limit=5),
            "workflow_runs": await queries.recent_workflow_runs(db, organization_id, limit=5),
            "findings": await queries.open_findings(db, organization_id, limit=10),
            "severity_order": queries.SEVERITY_ORDER,
            "actions": _actions(membership),
        },
        partial="partials/dashboard_body.html",
    )


#: One page size for every paginated dashboard listing. A constant rather
#: than a per-route number, so "page 2" means the same span of rows
#: wherever it appears.
PAGE_SIZE = 50


@router.get("/organizations/{organization_id}/findings", response_class=HTMLResponse)
async def findings_page(
    request: Request,
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Viewer,
    severity: Annotated[str | None, Query(max_length=20)] = None,
    page: Annotated[int, Query(ge=1)] = 1,
) -> HTMLResponse:
    offset = (page - 1) * PAGE_SIZE
    findings = await queries.open_findings(
        db, organization_id, severity=severity, limit=PAGE_SIZE, offset=offset
    )
    has_more = await queries.has_more_findings(
        db, organization_id, severity=severity, limit=PAGE_SIZE, offset=offset
    )
    return _page(
        request,
        "findings.html",
        {
            "membership": membership,
            "organization_id": organization_id,
            "findings": findings,
            "severity": (severity or "").upper(),
            "severity_order": queries.SEVERITY_ORDER,
            "actions": _actions(membership),
            "page": page,
            "has_prev": page > 1,
            "has_more": has_more,
        },
        partial="partials/findings_table.html",
    )


@router.get("/organizations/{organization_id}/runs", response_class=HTMLResponse)
async def runs_page(
    request: Request,
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Viewer,
    page: Annotated[int, Query(ge=1)] = 1,
) -> HTMLResponse:
    offset = (page - 1) * PAGE_SIZE
    runs = await queries.recent_runs(db, organization_id, limit=PAGE_SIZE, offset=offset)
    has_more = await queries.has_more_runs(db, organization_id, limit=PAGE_SIZE, offset=offset)
    return _page(
        request,
        "runs.html",
        {
            "membership": membership,
            "organization_id": organization_id,
            "runs": runs,
            "targets": {t.id: t.name for t in await queries.targets_for(db, organization_id)},
            "actions": _actions(membership),
            "page": page,
            "has_prev": page > 1,
            "has_more": has_more,
        },
        partial="partials/runs_table.html",
    )


@router.get("/organizations/{organization_id}/workflows", response_class=HTMLResponse)
async def workflows_page(
    request: Request, organization_id: uuid.UUID, db: DbSession, membership: Viewer
) -> HTMLResponse:
    workflows = list(
        (
            await db.execute(
                select(Workflow)
                .where(Workflow.organization_id == organization_id)
                .order_by(Workflow.name)
            )
        )
        .scalars()
        .all()
    )
    return _page(
        request,
        "workflows.html",
        {
            "membership": membership,
            "organization_id": organization_id,
            "workflows": workflows,
            "workflow_runs": await queries.recent_workflow_runs(db, organization_id, limit=50),
            "targets": {t.id: t.name for t in await queries.targets_for(db, organization_id)},
            "actions": _actions(membership),
        },
        partial="partials/workflow_runs_table.html",
    )


@router.get("/organizations/{organization_id}/targets", response_class=HTMLResponse)
async def targets_page(
    request: Request, organization_id: uuid.UUID, db: DbSession, membership: Viewer
) -> HTMLResponse:
    targets = await queries.targets_for(db, organization_id)
    return _page(
        request,
        "targets.html",
        {
            "membership": membership,
            "organization_id": organization_id,
            "targets": targets,
            "actions": _actions(membership),
        },
        partial="partials/targets_table.html",
    )


@router.get("/organizations/{organization_id}/repositories", response_class=HTMLResponse)
async def repositories_page(
    request: Request, organization_id: uuid.UUID, db: DbSession, membership: Viewer
) -> HTMLResponse:
    repositories = await queries.repositories_for(db, organization_id)
    return _page(
        request,
        "repositories.html",
        {
            "membership": membership,
            "organization_id": organization_id,
            "repositories": repositories,
            "actions": _actions(membership),
        },
        partial="partials/repositories_table.html",
    )


#: Actions the dashboard displays but does not perform, with the reason and the
#: thing that does perform them. §27 requires that a visible action either works
#: or says why it does not; a greyed-out button with no explanation fails that
#: as surely as one that silently does nothing.
_CSRF_REASON = (
    "The dashboard is read-only: write handlers are not built. CSRF protection "
    "now exists (docs/csrf.md), so this is a scope decision rather than a "
    "security constraint — the reason it was one has been removed. Use the API "
    "or the CLI."
)


def _actions(membership: Membership) -> dict[str, dict[str, str]]:
    """Every action the templates may render, resolved for this member.

    Returned from one place so a template cannot invent a button. `enabled` is
    always false today — see `_CSRF_REASON` — and `role_ok` is still computed,
    because "you may not do this" and "nothing here may do this" are different
    answers and an operator deserves the accurate one.
    """

    def action(label: str, needs: Role, how: str) -> dict[str, str]:
        permitted = membership.role.at_least(needs)
        return {
            "label": label,
            "enabled": "",
            "reason": _CSRF_REASON if permitted else f"Requires role '{needs.value}' or higher.",
            "how": how,
            "role_ok": "yes" if permitted else "",
        }

    return {
        "start_run": action(
            "Start a run",
            Role.SECURITY_ENGINEER,
            "POST /api/v1/organizations/{organization_id}/runs",
        ),
        "change_status": action(
            "Change a finding's status",
            Role.ANALYST,
            "PATCH /api/v1/organizations/{organization_id}/findings/{finding_id}",
        ),
        "run_workflow": action(
            "Run a workflow",
            Role.SECURITY_ENGINEER,
            "POST /api/v1/organizations/{organization_id}/workflows/{workflow_id}/runs",
        ),
        "add_target": action(
            "Add a target",
            Role.ADMIN,
            "POST /api/v1/organizations/{organization_id}/targets",
        ),
        "add_repository": action(
            "Connect a repository",
            Role.SECURITY_ENGINEER,
            "POST /api/v1/organizations/{organization_id}/repositories "
            "(or: aegis-ai repo add --name ... --url ... --authorized)",
        ),
        "scan_repository": action(
            "Scan a repository",
            Role.SECURITY_ENGINEER,
            "POST /api/v1/organizations/{organization_id}/repositories/{repository_id}/scan "
            "(or: aegis-ai repo scan <repository>)",
        ),
    }
