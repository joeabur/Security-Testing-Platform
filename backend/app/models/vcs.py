"""Code-host connections and what was posted to a pull request (§27).

As with `NotificationChannel`, note the absent column: there is no token here.
A connection stores the *name* of the environment variable that holds it, so
this schema cannot hold a credential even if a future caller tried.

`PullRequestPost` is the record of what this platform wrote into somebody's
pull request. It exists because writing into a customer's repository is the
most externally-visible thing the platform does, and "what did Kervy say on
PR 412?" should be answerable from our side without reading GitHub.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class VcsConnection(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "vcs_connections"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_vcs_connection_org_name"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Only for GitHub Enterprise. github.com's API host is pinned in code, so
    #: a row cannot redirect a `github` connection somewhere else.
    api_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: The variable name. Never the token.
    token_env_var: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class PullRequestPost(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "pull_request_posts"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    connection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vcs_connections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    assessment_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_runs.id", ondelete="SET NULL"), nullable=True
    )
    repo_slug: Mapped[str] = mapped_column(String(255), nullable=False)
    pull_number: Mapped[int] = mapped_column(Integer, nullable=False)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)

    conclusion: Mapped[str] = mapped_column(String(20), nullable=False)
    check_run_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    check_run_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    annotations_posted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: Findings that could not be anchored to a changed line. Recorded because
    #: "we posted 12 of 30" is a fact a reader needs, not one to infer.
    annotations_dropped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    posted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Scrubbed before it is written. Never a token, never a response body.
    detail: Mapped[str | None] = mapped_column(String(500), nullable=True)
    #: Fingerprints of what was reported, so a later post can be compared with
    #: this one without re-reading GitHub.
    fingerprints: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
