"""The "add a repository" API surface (app/core/repositories/service.py).

Deliberately a thin, opinionated shape over `Target`/`Authorization`/
`RulesOfEngagementRecord` rather than a general one: this is the fast path
for "I have a repository I want scanned," not a second way to configure
everything the full Target API already exposes. A user who needs the full
Rules-of-Engagement/Authorization workflow — a live network target, an
operator-granted authorization signed by someone else — uses that API
instead; this one is for source code someone already has read access to.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.assessment_run import RunStatus
from app.models.target import TargetEnvironment


class RepositoryCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    # Split into `url` + `branch` rather than the internal
    # `git+https://host/path#branch` shape the Target API uses — a user
    # adding a repository pastes a URL, not a scheme-prefixed reference.
    url: str = Field(min_length=1, max_length=2048)
    branch: str | None = Field(default=None, max_length=200)
    environment: TargetEnvironment = TargetEnvironment.PRODUCTION
    languages: list[str] = Field(default_factory=list, max_length=20)
    build_manifest_paths: list[str] = Field(default_factory=list, max_length=50)
    # Defaults to "scan everything" — the opposite default from the Target
    # API's `code_scope`, which fails closed with no default because it is
    # built for an operator narrowing a live assessment's boundary. Here the
    # boundary IS the repository the caller just named and consented to;
    # "everything in it" is the expected default, matching Aikido and
    # similar SCA/SAST tools, which scan a connected repository in full
    # unless told otherwise.
    allowed_paths: list[str] = Field(default_factory=lambda: ["**"], max_length=200)
    excluded_paths: list[str] = Field(default_factory=list, max_length=200)
    max_repo_size_mb: int = Field(default=500, ge=1, le=10_000)
    # The lightweight consent this endpoint exists to replace a full
    # Authorization-grant workflow with: not a signature from someone else,
    # but an explicit, audited affirmation from whoever is adding the
    # repository that they have the right to have it scanned. Rejected if
    # false rather than defaulted or ignored — the checkbox has to be
    # checked, not merely present.
    authorized: bool = False

    @field_validator("authorized")
    @classmethod
    def _must_be_affirmed(cls, value: bool) -> bool:
        if not value:
            raise ValueError(
                "authorized must be true: adding a repository requires affirming you "
                "have the right to have it scanned"
            )
        return value


class RepositoryScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    run_id: uuid.UUID = Field(validation_alias="id")
    status: RunStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str | None = None


class RepositoryRead(BaseModel):
    """Always built explicitly by the service layer, not `.model_validate()`'d
    off the `Target` row directly — `url`/`branch`/`latest_scan` are derived,
    not stored columns."""

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    url: str
    branch: str | None
    environment: TargetEnvironment
    languages: list[str]
    build_manifest_paths: list[str]
    created_at: datetime
    latest_scan: RepositoryScanSummary | None = None


class RepositoryDetail(RepositoryRead):
    allowed_paths: list[str]
    excluded_paths: list[str]
    max_repo_size_mb: int
    authorized_by_name: str
    authorized_at: datetime
    recent_scans: list[RepositoryScanSummary] = Field(default_factory=list)
    open_findings_by_severity: dict[str, int] = Field(default_factory=dict)


class RepositoryScanTrigger(BaseModel):
    safe_mode: bool = True


class RepositoryScanResult(BaseModel):
    run_id: uuid.UUID
    status: RunStatus
