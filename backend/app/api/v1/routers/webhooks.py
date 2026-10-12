"""The inbound webhook endpoints (pentest-module Phase 8; GitHub support
added later).

Deliberately **not** nested under `/organizations/{organization_id}/...`.
`tests/security/test_authorization_matrix.py` asserts every route under
that prefix declares a minimum role — correctly, since that prefix *is*
this platform's authorization boundary. An inbound webhook has no
session or JWT for any organization at all; its authentication is an
HMAC signature, not membership. Nesting it there would need a
special-cased exemption to an otherwise-clean invariant, so it lives here
instead, at the top level, the same way `/auth/csrf` is a public,
non-organization-scoped route.

`workflow_id` alone (an unguessable UUID) identifies the workflow; its own
`organization_id` column is read from the loaded row. This mirrors the
one already-established pattern in this codebase for "look up by opaque
UUID before any tenant context exists" —
`app/workers/tasks.py::execute_assessment_run` loads its `AssessmentRun`
by bare id and calls `set_tenant_context` immediately after, before any
further query; both handlers below do the same immediately after loading
`Workflow`.

Two receivers, one secret per workflow (`Workflow.webhook_secret_encrypted`):
the original endpoint speaks this platform's own `signing.py` scheme, and
`/webhooks/github/workflows/{id}` speaks GitHub's own
(`github_signing.py`) — an operator picks whichever URL matches where the
delivery comes from, using the one secret `POST .../webhook-secret`
already issued. Neither widens what the other accepts.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import ValidationError

from app.auth.dependencies import DbSession
from app.core.config import get_settings
from app.core.integrations import github_signing, signing
from app.core.ratelimit import dependency as ratelimit
from app.core.workflow import service as workflow_service
from app.core.workflow.contract import TriggerKind
from app.core.workflow.replay_guard import (
    WebhookReplayed,
    WebhookReplayGuard,
    WebhookReplayGuardUnavailable,
)
from app.core.workflow.webhook_secret import WebhookEncryptionNotConfigured, decrypt_secret
from app.db.tenant_context import set_tenant_context
from app.models.workflow import Workflow
from app.schemas.workflow import InboundWebhookTrigger

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

#: GitHub has no timestamp in its own signature scheme, so the replay guard
#: here is the only defense against replay, not a backstop on an
#: independent age check — see `replay_guard.py`'s own docstring. 24 hours
#: comfortably covers GitHub's own documented redelivery window for a
#: failed delivery, while still being a bounded window rather than "forever".
_GITHUB_REPLAY_TTL_SECONDS = 24 * 60 * 60

#: `pull_request` actions that represent new or changed code worth scanning.
#: Everything else GitHub can send for this event (`labeled`, `assigned`,
#: `closed`, review-related actions, …) is accepted but triggers nothing —
#: an operator subscribing to the whole event is not asking for a scan on
#: every one of its actions.
_PULL_REQUEST_TRIGGERING_ACTIONS = frozenset({"opened", "synchronize", "reopened"})

#: A deleted-branch push's `after` is this — forty zeros. There is nothing
#: to scan once a branch is gone.
_DELETED_BRANCH_SHA = "0" * 40


async def _load_webhook_workflow(db: DbSession, workflow_id: uuid.UUID) -> Workflow:
    # `webhook_enabled=False` and "does not exist" are deliberately not
    # distinguishable: an attacker probing ids learns nothing about which
    # workflows exist and have webhooks configured.
    workflow = await db.get(Workflow, workflow_id)
    if (
        workflow is None
        or not workflow.webhook_enabled
        or workflow.webhook_secret_encrypted is None
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="not found")
    return workflow


def _decrypt_webhook_secret(workflow: Workflow) -> str:
    # `_load_webhook_workflow` already refused a workflow with no secret;
    # this narrows the type for mypy rather than re-deciding the business
    # rule here.
    encrypted = workflow.webhook_secret_encrypted
    assert encrypted is not None
    try:
        return decrypt_secret(encrypted, key=get_settings().webhook_secret_encryption_key_bytes)
    except WebhookEncryptionNotConfigured as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


async def _claim_replay_key(key: str, *, ttl_seconds: int | None = None) -> None:
    try:
        kwargs = {} if ttl_seconds is None else {"ttl_seconds": ttl_seconds}
        await WebhookReplayGuard().mark_seen_or_raise(key, **kwargs)
    except WebhookReplayed as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except WebhookReplayGuardUnavailable as exc:
        # Fail closed: an unreadable dedup check must never be treated as
        # "unseen, so accept it" — see replay_guard.py's own docstring.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="replay protection unavailable"
        ) from exc


async def _trigger_and_respond(
    db: DbSession, workflow: Workflow, payload: InboundWebhookTrigger, *, actor: str
) -> dict[str, str]:
    await set_tenant_context(db, workflow.organization_id)
    trigger = workflow_service.trigger_from(
        workflow,
        kind=payload.kind,
        ref=payload.ref,
        commit=payload.commit,
        pull_number=payload.pull_number,
        actor=actor,
        unattended=True,
    )
    run, outcome = await workflow_service.start_and_maybe_pause(db, workflow, trigger)
    if run.status == "awaiting_approval":
        await db.commit()
        return {"workflow_run_id": str(run.id), "status": run.status}

    await workflow_service.finish(db, run, workflow, outcome, actions_detail="triggered by webhook")
    await db.commit()
    return {"workflow_run_id": str(run.id), "status": run.status}


@router.post("/workflows/{workflow_id}", status_code=status.HTTP_202_ACCEPTED)
async def receive_workflow_webhook(
    workflow_id: uuid.UUID, request: Request, db: DbSession
) -> dict[str, str]:
    # Before anything else: no session or JWT authenticates this route, so
    # a flood costs a signature check and a Redis round trip each before
    # being refused for any other reason — see `policy.py`'s own "Choosing
    # the numbers" for why this budget exists on top of `api_default`'s.
    await ratelimit.enforce(request, "webhook_inbound", identity=str(workflow_id))
    body = await request.body()
    signature = request.headers.get(signing.SIGNATURE_HEADER)
    timestamp = request.headers.get(signing.TIMESTAMP_HEADER)
    if not signature or not timestamp:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="missing signature headers")

    workflow = await _load_webhook_workflow(db, workflow_id)
    secret = _decrypt_webhook_secret(workflow)

    if not signing.verify(secret, body, timestamp=timestamp, signature=signature):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="signature verification failed")

    await _claim_replay_key(signature)

    try:
        payload = InboundWebhookTrigger.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    return await _trigger_and_respond(db, workflow, payload, actor=f"webhook:{workflow.id}")


@router.post("/github/workflows/{workflow_id}", status_code=status.HTTP_202_ACCEPTED)
async def receive_github_workflow_webhook(
    workflow_id: uuid.UUID, request: Request, db: DbSession
) -> dict[str, str]:
    await ratelimit.enforce(request, "webhook_inbound", identity=str(workflow_id))
    body = await request.body()
    signature = request.headers.get(github_signing.SIGNATURE_HEADER)
    delivery = request.headers.get(github_signing.DELIVERY_HEADER)
    event = request.headers.get(github_signing.EVENT_HEADER)
    if not delivery or not event:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="missing X-GitHub-Delivery or X-GitHub-Event"
        )

    workflow = await _load_webhook_workflow(db, workflow_id)
    secret = _decrypt_webhook_secret(workflow)

    if not github_signing.verify(secret, body, signature):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="signature verification failed")

    # Claimed by delivery id, not the signature — GitHub resends the exact
    # same delivery id (and signature) on a retried redelivery, which this
    # correctly rejects the second time; a distinct new event always gets a
    # fresh id. See the module-level TTL constant and replay_guard.py's own
    # docstring for why this window is much longer than the native route's.
    await _claim_replay_key(delivery, ttl_seconds=_GITHUB_REPLAY_TTL_SECONDS)

    if event == "ping":
        # Sent once, when the webhook is first configured in GitHub's UI,
        # so an operator sees success there without this triggering a run.
        return {"workflow_run_id": "", "status": "ignored"}

    try:
        raw: Any = json.loads(body)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    if not isinstance(raw, dict):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="not a JSON object")

    payload = _github_payload_to_trigger(event, raw)
    if payload is None:
        # A real GitHub event this route is simply not wired to act on
        # (another event type entirely, or a `pull_request` action that is
        # not a code change) — accepted, not an error, nothing to trigger.
        return {"workflow_run_id": "", "status": "ignored"}

    return await _trigger_and_respond(db, workflow, payload, actor=f"webhook:github:{workflow.id}")


def _github_payload_to_trigger(event: str, raw: dict[str, Any]) -> InboundWebhookTrigger | None:
    """GitHub's own push/pull_request event shapes, mapped onto this
    platform's minimal trigger shape. `None` means "nothing to trigger",
    not "malformed" — see the callers for why each case returns it."""
    if event == "push":
        after = raw.get("after")
        if raw.get("deleted") is True or after == _DELETED_BRANCH_SHA:
            return None
        ref = raw.get("ref")
        if not isinstance(ref, str) or not isinstance(after, str):
            return None
        return InboundWebhookTrigger(kind=TriggerKind.REPOSITORY_CHANGE, ref=ref, commit=after)

    if event == "pull_request":
        if raw.get("action") not in _PULL_REQUEST_TRIGGERING_ACTIONS:
            return None
        pull_request = raw.get("pull_request")
        if not isinstance(pull_request, dict):
            return None
        head = pull_request.get("head")
        number = pull_request.get("number")
        if not isinstance(head, dict) or not isinstance(number, int):
            return None
        ref, sha = head.get("ref"), head.get("sha")
        if not isinstance(ref, str) or not isinstance(sha, str):
            return None
        return InboundWebhookTrigger(
            kind=TriggerKind.PULL_REQUEST, ref=ref, commit=sha, pull_number=number
        )

    # Any other event GitHub can be configured to send (issues, releases,
    # stars, …) is a real delivery this route has nothing to do with.
    return None
