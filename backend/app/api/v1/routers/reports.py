"""Report and evidence download endpoints (docs/BUILD_SPEC.md §13, §14).

Two rules shape this module.

**No public URLs.** Every route below is behind the same membership check as
the rest of the API, so an evidence bundle or a report is reachable only by a
member of the organization that owns the run. There is no signed link, no
share token, and no unauthenticated export — §13 is explicit that evidence
must not be retrievable without authorization, and the simplest way to keep
that true is to offer no other path to it.

**Every download is audited.** A report is the artefact that leaves the
platform, and evidence is the rawest material it holds. Who took a copy, of
what, and when is part of the record, so each handler writes an audit event
before returning bytes.
"""

import re
import uuid
from enum import StrEnum

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.core.config import get_settings
from app.core.evidence.store import EvidenceError, EvidenceStore, build_evidence_store
from app.core.reporting.build import build_report, report_filename, to_canonical_json
from app.core.reporting.render import (
    PdfUnavailableError,
    render_csv,
    render_html,
    render_markdown,
    render_pdf,
)
from app.core.reporting.sarif import to_sarif_json
from app.core.reporting.templates import Template
from app.models.assessment_run import AssessmentRun, RunStatus
from app.models.organization import Membership, Role
from app.models.target import Target
from app.schemas.report import EvidenceManifestEntryRead, EvidenceVerificationRead

router = APIRouter(prefix="/organizations/{organization_id}/runs/{run_id}", tags=["reports"])

# A digest names a file inside the store. Constrained here so nothing that
# could climb out of the bundles directory ever reaches the filesystem, even
# though the store joins the name itself.
_DIGEST = re.compile(r"^(sha256:)?[0-9a-f]{64}$")

# Runs with nothing to report on. A report from a run that never started
# would be a document full of zeroes that reads like a clean result.
_NOT_YET_RUN = frozenset({RunStatus.DRAFT, RunStatus.QUEUED})


class ReportFormat(StrEnum):
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    SARIF = "sarif"
    CSV = "csv"


_MEDIA_TYPES = {
    ReportFormat.MARKDOWN: "text/markdown; charset=utf-8",
    ReportFormat.HTML: "text/html; charset=utf-8",
    ReportFormat.PDF: "application/pdf",
    ReportFormat.JSON: "application/json",
    ReportFormat.SARIF: "application/sarif+json",
    ReportFormat.CSV: "text/csv; charset=utf-8",
}

_EXTENSIONS = {
    ReportFormat.MARKDOWN: "md",
    ReportFormat.HTML: "html",
    ReportFormat.PDF: "pdf",
    ReportFormat.JSON: "json",
    ReportFormat.SARIF: "sarif.json",
    ReportFormat.CSV: "csv",
}


def get_evidence_store() -> EvidenceStore:
    """The evidence store, as a dependency so a test can point it elsewhere."""
    return build_evidence_store(get_settings())


async def _load_run_and_target(
    organization_id: uuid.UUID, run_id: uuid.UUID, db: DbSession
) -> tuple[AssessmentRun, Target]:
    run = (
        await db.execute(
            select(AssessmentRun).where(
                AssessmentRun.id == run_id,
                AssessmentRun.organization_id == organization_id,
            )
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Run not found")

    # Every relationship the report reads is loaded here: a lazy load in the
    # middle of rendering would raise, because these sessions are async.
    target = (
        await db.execute(
            select(Target)
            .where(Target.id == run.target_id)
            .options(
                selectinload(Target.authorization),
                selectinload(Target.rules_of_engagement),
                selectinload(Target.surface_endpoints),
            )
        )
    ).scalar_one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Target not found")
    return run, target


@router.get("/report")
async def download_report(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    request: Request,
    db: DbSession,
    report_format: ReportFormat = ReportFormat.MARKDOWN,
    template: Template = Template.TECHNICAL,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> Response:
    """Render this run's report in one of §14's formats.

    The same `ReportData` feeds every format, so the executive PDF and the
    SARIF upload cannot disagree about what was found.
    """
    run, target = await _load_run_and_target(organization_id, run_id, db)
    if run.status in _NOT_YET_RUN:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                f"run is {run.status.value}; there is nothing to report on yet. "
                "A report is only meaningful once the run has executed."
            ),
        )

    report = await build_report(db, run=run, target=target)

    body: bytes
    if report_format is ReportFormat.MARKDOWN:
        body = render_markdown(report, template).encode()
    elif report_format is ReportFormat.HTML:
        body = render_html(report, template).encode()
    elif report_format is ReportFormat.PDF:
        try:
            body = render_pdf(report, template)
        except PdfUnavailableError as exc:
            raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc
    elif report_format is ReportFormat.JSON:
        body = to_canonical_json(report).encode()
    elif report_format is ReportFormat.SARIF:
        body = to_sarif_json(report).encode()
    else:
        body = render_csv(report).encode()

    filename = report_filename(run.id, template.value, _EXTENSIONS[report_format])

    await record_event(
        db,
        action="report.download",
        resource_type="run",
        resource_id=str(run.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={
            "format": report_format.value,
            "template": template.value,
            "findings": len(report.findings),
            "bytes": len(body),
        },
    )
    await db.commit()

    return Response(
        content=body,
        media_type=_MEDIA_TYPES[report_format],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/evidence", response_model=list[EvidenceManifestEntryRead])
async def list_evidence(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    db: DbSession,
    store: EvidenceStore = Depends(get_evidence_store),  # noqa: B008
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[EvidenceManifestEntryRead]:
    """The run's evidence manifest — digests and chain values, not contents."""
    await _load_run_and_target(organization_id, run_id, db)
    return [
        EvidenceManifestEntryRead(
            sequence=entry.sequence,
            digest=entry.digest,
            previous=entry.previous,
            chain=entry.chain,
            probe_id=entry.probe_id,
            created_at=entry.created_at,
        )
        for entry in store.read_manifest(str(run_id))
    ]


@router.get("/evidence/verify", response_model=EvidenceVerificationRead)
async def verify_evidence(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    db: DbSession,
    store: EvidenceStore = Depends(get_evidence_store),  # noqa: B008
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> EvidenceVerificationRead:
    """Re-check the chain and every bundle's content against its digest.

    Exposed to readers, not just operators: "the evidence is intact" is only
    a useful claim if the person reading the report can check it.
    """
    await _load_run_and_target(organization_id, run_id, db)
    result = store.verify(str(run_id))
    return EvidenceVerificationRead(
        ok=result.ok, entries=result.entries, problems=list(result.problems)
    )


@router.get("/evidence/{digest}")
async def download_evidence(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    digest: str,
    request: Request,
    db: DbSession,
    store: EvidenceStore = Depends(get_evidence_store),  # noqa: B008
    membership: Membership = Depends(require_membership(Role.ANALYST)),  # noqa: B008
) -> Response:
    """One evidence bundle, as it was written.

    Analyst and above rather than viewer: the bundle is redacted, but it is
    still the closest thing the platform keeps to the raw exchange with the
    target, and a read-only reporting account has no need for it.
    """
    if not _DIGEST.match(digest):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="digest must be a sha256 hex digest, optionally 'sha256:'-prefixed",
        )

    await _load_run_and_target(organization_id, run_id, db)
    try:
        payload = store.read(str(run_id), digest)
    except EvidenceError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    await record_event(
        db,
        action="evidence.download",
        resource_type="evidence_bundle",
        resource_id=digest,
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"run_id": str(run_id), "bytes": len(payload)},
    )
    await db.commit()

    short = digest.removeprefix("sha256:")[:16]
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="evidence-{short}.json"'},
    )
