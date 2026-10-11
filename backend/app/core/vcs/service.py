"""Publishing a run's findings to a pull request.

The order of operations is the interesting part, because each step can fail in
a way the next must not paper over:

1. **Resolve the connection.** Token from the environment, host pinned or
   sanctioned. A failure here is final — the same configuration fails the same
   way — and is recorded as a refusal rather than retried.
2. **Read the diff first.** Before deciding what to say, find out which lines
   GitHub will actually render an annotation on. Doing this after building the
   check run would mean discovering the answer too late to move the unanchored
   findings into the body.
3. **Evaluate the gate.** The check run's conclusion comes from the same
   `evaluate()` the CI gate uses, so a pull request and a pipeline cannot
   disagree about whether the same findings are a blocker.
4. **Post once.** One check run carrying everything, rather than a check run
   plus a review: two writes mean two chances to half-succeed, and a review
   comment on a line the check run already annotated is the same message twice.

Nothing here writes to the repository. See `contract.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_event
from app.core.config import Settings, get_settings
from app.core.gate.evaluate import evaluate
from app.core.gate.model import GateConfig, GateDecision, GateFinding
from app.core.integrations.dispatch import scrub
from app.core.probes.models import Confidence, Severity
from app.core.vcs.contract import (
    Destination,
    PostOutcome,
    PullRequestRef,
    RepoRef,
    VcsError,
    VcsProvider,
    diff_index,
)
from app.core.vcs.egress import vcs_egress_context
from app.core.vcs.github import GitHubClient
from app.core.vcs.policy import resolve_destination
from app.core.vcs.render import PublishableFinding, check_run_for
from app.models.finding import Finding
from app.models.vcs import PullRequestPost, VcsConnection

#: The gate a pull request is judged by when the caller supplies none. Matches
#: the CLI's default so the two do not disagree, and errs towards reporting: a
#: check run that fails only on critical is one a team will trust.
DEFAULT_GATE = GateConfig(
    fail_on=(Severity.CRITICAL,),
    min_confidence=Confidence.MEDIUM,
    max_high=None,
    max_medium=None,
)


def publishable(finding: Finding, run_id: uuid.UUID | None) -> PublishableFinding:
    return PublishableFinding(
        fingerprint=finding.fingerprint,
        title=finding.title,
        severity=str(getattr(finding.severity, "value", finding.severity)).upper(),
        surface=finding.surface,
        probe_id=finding.probe_id,
        severity_rationale=finding.severity_rationale or "",
        remediation=finding.remediation or "",
        # "New" means first seen in the run being published. A pull request
        # that touched one file must not be presented as having introduced
        # everything the repository already had.
        is_new=run_id is not None and finding.first_run_id == run_id,
    )


def gate_findings(findings: Sequence[PublishableFinding]) -> list[GateFinding]:
    return [
        GateFinding(
            fingerprint=finding.fingerprint,
            title=finding.title,
            severity=Severity(finding.severity),
            confidence=Confidence.HIGH,
            stability="deterministic",
            status="new" if finding.is_new else "confirmed",
        )
        for finding in findings
        if finding.severity in {item.value for item in Severity}
    ]


async def findings_for_run(
    db: AsyncSession, organization_id: uuid.UUID, run_id: uuid.UUID
) -> list[Finding]:
    result = await db.execute(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.last_run_id == run_id,
            # The same exclusion `app/core/reporting/build.py` already
            # applies to a run's own report: a finding a human has
            # explicitly linked as a duplicate of another
            # (app/core/findings/service.py::link_duplicate) must not also
            # count twice toward a PR check run or the gate it is judged
            # by — that is the whole point of recording the link.
            Finding.duplicate_of_finding_id.is_(None),
        )
    )
    return list(result.scalars().all())


def destination_for(
    connection: VcsConnection,
    *,
    settings: Settings | None = None,
    environ: Mapping[str, str] | None = None,
) -> Destination:
    config = settings or get_settings()
    try:
        provider = VcsProvider(connection.provider)
    except ValueError as exc:
        raise VcsError(f"unknown code host provider {connection.provider!r}") from exc
    return resolve_destination(
        provider,
        connection.token_env_var,
        api_host=connection.api_host,
        operator_hosts=config.vcs_allowed_hosts,
        environ=environ,
    )


async def publish(
    db: AsyncSession,
    connection: VcsConnection,
    *,
    repo: RepoRef,
    pull_number: int,
    head_sha: str,
    findings: Sequence[Finding],
    run_id: uuid.UUID | None = None,
    config: GateConfig | None = None,
    settings: Settings | None = None,
    environ: Mapping[str, str] | None = None,
    client: GitHubClient | None = None,
) -> tuple[PullRequestPost, PostOutcome]:
    """Post one check run, record it, and audit it."""
    app_settings = settings or get_settings()
    publishables = [publishable(finding, run_id) for finding in findings]
    decision: GateDecision = evaluate(gate_findings(publishables), config or DEFAULT_GATE)

    post = PullRequestPost(
        organization_id=connection.organization_id,
        connection_id=connection.id,
        assessment_run_id=run_id,
        repo_slug=repo.slug,
        pull_number=pull_number,
        head_sha=head_sha,
        conclusion="neutral",
        findings_total=len(publishables),
        fingerprints=[item.fingerprint for item in publishables],
    )
    db.add(post)
    await db.flush()

    outcome = PostOutcome(posted=False)
    try:
        destination = destination_for(connection, settings=app_settings, environ=environ)
        api = client or GitHubClient(destination)
        ctx = vcs_egress_context(destination)
        pull = PullRequestRef(repo=repo, number=pull_number, head_sha=head_sha)

        # Before deciding what to say: where can it be said?
        diff = diff_index(await api.pull_request_files(ctx, pull))
        request, anchored, unanchored = check_run_for(
            publishables,
            decision,
            head_sha=head_sha,
            diff=diff,
            details_url=(
                f"{app_settings.public_base_url.rstrip('/')}/runs/{run_id}"
                if app_settings.public_base_url and run_id
                else None
            ),
        )
        outcome = await api.create_check_run(ctx, repo, request)
        post.conclusion = request.conclusion.value
        post.check_run_id = outcome.check_run_id
        post.check_run_url = outcome.check_run_url
        post.annotations_posted = anchored
        post.annotations_dropped = unanchored
        post.posted_at = datetime.now(UTC)
        post.detail = scrub(outcome.detail)[:500]
    except VcsError as exc:
        post.detail = scrub(str(exc))[:500]
        outcome = PostOutcome(posted=False, detail=post.detail)

    await record_event(
        db,
        action="pull_request.published" if outcome.posted else "pull_request.refused",
        resource_type="pull_request_post",
        resource_id=str(post.id),
        result="allow" if outcome.posted else "deny",
        organization_id=connection.organization_id,
        metadata={
            "repo": repo.slug,
            "pull_number": pull_number,
            "head_sha": head_sha,
            "conclusion": post.conclusion,
            "findings": len(publishables),
            "annotations_posted": post.annotations_posted,
            "annotations_dropped": post.annotations_dropped,
            "detail": post.detail,
        },
    )
    return post, outcome
