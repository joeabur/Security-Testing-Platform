"""The inbound webhook endpoint (pentest-module Phase 8).

Deliberately **not** nested under `/organizations/{organization_id}/...`.
`tests/security/test_authorization_matrix.py` asserts every route under
that prefix declares a minimum role — correctly, since that prefix *is*
this platform's authorization boundary. An inbound webhook has no
session or JWT for any organization at all; its authentication is the
HMAC signature (`app.core.integrations.signing`), not membership. Nesting
it there would need a special-cased exemption to an otherwise-clean
invariant, so it lives here instead, at the top level, the same way
`/auth/csrf` is a public, non-organization-scoped route.

`workflow_id` alone (an unguessable UUID) identifies the workflow; its own
`organization_id` column is read from the loaded row. This mirrors the
one already-established pattern in this codebase for "look up by opaque
UUID before any tenant context exists" —
`app/workers/tasks.py::execute_assessment_run` loads its `AssessmentRun`
by bare id and calls `set_current_organization` immediately after, before
any further query; this handler does the same immediately after loading
`Workflow`.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import ValidationError

from app.auth.dependencies import DbSession
from app.core.config import get_settings
from app.core.integrations import signing
from app.core.workflow import service as workflow_service
from app.core.workflow.replay_guard import (
    WebhookReplayed,
    WebhookReplayGuard,
    WebhookReplayGuardUnavailable,
)
from app.core.workflow.webhook_secret import WebhookEncryptionNotConfigured, decrypt_secret
from app.db.tenant_context import set_current_organization
from app.models.workflow import Workflow
from app.schemas.workflow import InboundWebhookTrigger

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/workflows/{workflow_id}", status_code=status.HTTP_202_ACCEPTED)
async def receive_workflow_webhook(
    workflow_id: uuid.UUID, request: Request, db: DbSession
) -> dict[str, str]:
    body = await request.body()
    signature = request.headers.get(signing.SIGNATURE_HEADER)
    timestamp = request.headers.get(signing.TIMESTAMP_HEADER)
    if not signature or not timestamp:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="missing signature headers")

    # Looked up by bare id, before any tenant context exists — see the
    # module docstring. `webhook_enabled=False` and "does not exist" are
    # deliberately not distinguishable: an attacker probing ids learns
    # nothing about which workflows exist and have webhooks configured.
    workflow = await db.get(Workflow, workflow_id)
    if (
        workflow is None
        or not workflow.webhook_enabled
        or workflow.webhook_secret_encrypted is None
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="not found")

    try:
        secret = decrypt_secret(
            workflow.webhook_secret_encrypted,
            key=get_settings().webhook_secret_encryption_key_bytes,
        )
    except WebhookEncryptionNotConfigured as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    if not signing.verify(secret, body, timestamp=timestamp, signature=signature):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="signature verification failed")

    try:
        await WebhookReplayGuard().mark_seen_or_raise(signature)
    except WebhookReplayed as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except WebhookReplayGuardUnavailable as exc:
        # Fail closed: an unreadable dedup check must never be treated as
        # "unseen, so accept it" — see replay_guard.py's own docstring.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="replay protection unavailable"
        ) from exc

    try:
        payload = InboundWebhookTrigger.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    set_current_organization(workflow.organization_id)
    trigger = workflow_service.trigger_from(
        workflow,
        kind=payload.kind,
        ref=payload.ref,
        commit=payload.commit,
        pull_number=payload.pull_number,
        actor=f"webhook:{workflow.id}",
        unattended=True,
    )
    run, outcome = await workflow_service.start_and_maybe_pause(db, workflow, trigger)
    if run.status == "awaiting_approval":
        await db.commit()
        return {"workflow_run_id": str(run.id), "status": run.status}

    await workflow_service.finish(db, run, workflow, outcome, actions_detail="triggered by webhook")
    await db.commit()
    return {"workflow_run_id": str(run.id), "status": run.status}
