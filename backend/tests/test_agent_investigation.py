"""`app/core/agent/investigation.py`: the in-memory state machine an
investigation moves through, and the fields it never carries (no request
text, no tool output — see the module docstring)."""

from __future__ import annotations

import uuid

from app.core.agent.investigation import Investigation, InvestigationStatus, PendingApproval
from app.core.agent.tools.contract import RiskLevel


def _investigation() -> Investigation:
    return Investigation.start(organization_id=uuid.uuid4(), user_id=uuid.uuid4())


def test_start_creates_a_running_investigation_with_no_pending_approval() -> None:
    investigation = _investigation()
    assert investigation.status is InvestigationStatus.RUNNING
    assert investigation.plan_step_index == 0
    assert investigation.pending_approval is None


def test_await_approval_pauses_and_records_the_pending_tool() -> None:
    investigation = _investigation()
    pending = PendingApproval(
        tool_name="start_scan", risk_level=RiskLevel.SENSITIVE, description="Queue a scan"
    )

    investigation.await_approval(pending)

    assert investigation.status is InvestigationStatus.AWAITING_APPROVAL
    assert investigation.pending_approval == pending


def test_resume_clears_the_pending_approval_and_advances_the_step() -> None:
    investigation = _investigation()
    investigation.await_approval(
        PendingApproval(
            tool_name="start_scan", risk_level=RiskLevel.SENSITIVE, description="Queue a scan"
        )
    )

    investigation.resume()

    assert investigation.status is InvestigationStatus.RUNNING
    assert investigation.pending_approval is None
    assert investigation.plan_step_index == 1


def test_complete_cancel_and_fail_each_clear_any_pending_approval() -> None:
    for terminal, expected in (
        (Investigation.complete, InvestigationStatus.COMPLETED),
        (Investigation.cancel, InvestigationStatus.CANCELLED),
        (Investigation.fail, InvestigationStatus.FAILED),
    ):
        investigation = _investigation()
        investigation.await_approval(
            PendingApproval(tool_name="t", risk_level=RiskLevel.SENSITIVE, description="d")
        )

        terminal(investigation)

        assert investigation.status is expected
        assert investigation.pending_approval is None


def test_an_investigations_natural_language_request_has_nowhere_to_live() -> None:
    """Structural proof of the zero-persistence promise: `Investigation` has
    no field a caller could even put a prompt or tool output into."""
    fields = set(Investigation.__dataclass_fields__)
    forbidden = {"request", "prompt", "messages", "history", "tool_output", "context"}
    assert fields & forbidden == set()
