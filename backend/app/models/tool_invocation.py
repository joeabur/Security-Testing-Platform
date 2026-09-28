"""Exactly which tool ran, with which network posture, and when — one row
per subprocess a run's engines invoke (docs/roadmap.md "record exactly which
tools, tests, and checks were executed").

Populated by `app.core.appsec.tooling.run_tool()` itself, once, for every
invocation across every engine — existing (Semgrep, Bandit, Trivy, Checkov,
pip-audit) and new (skopeo/Trivy image mode, cloud SDK calls, nmap,
Metasploit's RPC client). Nothing computes this after the fact from logs;
it is written at the moment the subprocess is launched, and again when it
finishes, the same "record what actually happened" discipline the evidence
store and audit log already follow.

`network_use` mirrors `app.core.appsec.tooling.NetworkUse`'s values as a
plain string rather than importing that enum into the model layer —
consistent with how `Workflow.trigger_kind` is already stored (a core-layer
enum's `.value`, not a second Postgres enum type to migrate every time a
new value is added).
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RunToolInvocation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "run_tool_invocations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_runs.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(120), nullable=False)
    tool_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    network_use: Mapped[str] = mapped_column(String(30), nullable=False)
    # A redacted summary of the invocation (binary + non-secret args), never
    # the raw command — the same "describe, don't dump" rule the audit log's
    # `metadata_json` and the notification dispatcher's `last_error` follow.
    command_summary: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
