"""Verifying a GitHub webhook delivery (`X-Hub-Signature-256`).

A second scheme alongside `signing.py`'s, not a replacement: this one is
GitHub's own, documented at
https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
— `sha256=<hex>`, an HMAC-SHA256 over the exact raw body, using the secret
configured on the GitHub webhook. A receiver has to speak GitHub's scheme
to accept GitHub's own deliveries; it cannot ask GitHub to sign the way
this platform signs its own outbound webhooks.

**There is no timestamp in this scheme.** `signing.py`'s own scheme signs
`v1:<timestamp>:<body>` specifically so a receiver can bound how old an
accepted delivery may be; GitHub signs the body alone, so a captured
delivery's signature stays valid to replay for as long as the secret
itself does. `app/core/workflow/replay_guard.py`'s dedup window has to be
sized with that in mind — see its own docstring for the consequence.
"""

from __future__ import annotations

import hashlib
import hmac

SIGNATURE_HEADER = "X-Hub-Signature-256"
EVENT_HEADER = "X-GitHub-Event"
DELIVERY_HEADER = "X-GitHub-Delivery"

_PREFIX = "sha256="


def verify(secret: str, body: bytes, signature: str | None) -> bool:
    """Constant-time check of GitHub's `sha256=<hex>` header against these
    exact bytes. `False` for a missing header, an unrecognised prefix, or a
    mismatch — never an exception a caller could forget to catch."""
    if not signature or not signature.startswith(_PREFIX):
        return False
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"{_PREFIX}{digest}", signature)
