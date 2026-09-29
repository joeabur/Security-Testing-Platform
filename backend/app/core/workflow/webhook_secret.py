"""Generating, encrypting, and decrypting a workflow's inbound webhook secret.

Unlike evidence-at-rest encryption (`app/core/evidence/crypto.py`), this is
not optional: an HMAC secret must never sit in Postgres in cleartext, and
verifying an inbound signature needs the raw secret back (a one-way hash,
`ApiKey`'s own storage shape, cannot be verified against without the caller
proving they already hold it — which is exactly what a webhook delivery
cannot do). So encryption here is mandatory rather than best-effort: with no
`AEGIS_WEBHOOK_SECRET_ENCRYPTION_KEY` configured, webhook automation simply
cannot be enabled, the same "state what's missing, not what to work around"
choice as an unconfigured PDF-reporting extra.

The secret itself is shown to the operator exactly once, at generation time
— the same UX as an API key's plaintext token (`app/models/api_key.py`).
"""

from __future__ import annotations

import secrets

from app.core.evidence.crypto import decrypt, encrypt


class WebhookEncryptionNotConfigured(Exception):
    """`AEGIS_WEBHOOK_SECRET_ENCRYPTION_KEY` is not set. Webhook automation
    cannot be enabled on this deployment until it is."""


def generate_secret() -> str:
    """A fresh, high-entropy secret. Never derived from anything the caller
    supplies — the operator gets exactly what this generates."""
    return secrets.token_urlsafe(32)


def encrypt_secret(secret: str, *, key: bytes | None) -> bytes:
    if key is None:
        raise WebhookEncryptionNotConfigured(
            "AEGIS_WEBHOOK_SECRET_ENCRYPTION_KEY must be set before a workflow's webhook "
            "can be enabled"
        )
    return encrypt(secret.encode("utf-8"), key=key)


def decrypt_secret(ciphertext: bytes, *, key: bytes | None) -> str:
    if key is None:
        raise WebhookEncryptionNotConfigured(
            "AEGIS_WEBHOOK_SECRET_ENCRYPTION_KEY must be set to verify an inbound webhook"
        )
    return decrypt(ciphertext, key=key).decode("utf-8")
