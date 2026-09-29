"""RFC 6238 TOTP: generating a shared secret, the `otpauth://` URI an
authenticator app scans, and verifying a submitted code.

A narrow wrapper over `pyotp` rather than a hand-rolled HMAC implementation
— the same choice this platform already made for AES-GCM (`cryptography`)
and password hashing (`argon2-cffi`): don't reimplement a primitive a
maintained library already gets right.

The shared secret itself is encrypted at rest with
`app.core.evidence.crypto.encrypt`/`decrypt`, keyed by
`Settings.totp_encryption_key_bytes` — the same AES-256-GCM helper
`app.core.workflow.webhook_secret` uses for the same reason: this secret is
exactly as sensitive as a webhook secret (either lets someone impersonate
the account it belongs to).
"""

from __future__ import annotations

import pyotp

from app.core.evidence.crypto import decrypt, encrypt

ISSUER = "Kervy Security"

#: Accepts the current 30-second step plus one on either side, so a
#: verification does not fail merely because the caller's clock and the
#: server's disagree by up to ~30s — a real and common case, not a
#: theoretical one. Widening it further would start trading real security
#: margin (a guessed code becomes valid for longer) for convenience nobody
#: has asked for.
_VALID_WINDOW = 1


class TotpNotConfigured(Exception):
    """No `KERVY_TOTP_ENCRYPTION_KEY` is set. Two-factor authentication
    cannot be enabled on this deployment until an operator sets one —
    mirrors `app.core.workflow.webhook_secret`'s refusal for the same
    reason: this secret must never be stored unencrypted."""


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, *, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)


def verify_code(secret: str, code: str) -> bool:
    code = code.strip()
    if not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=_VALID_WINDOW)


def encrypt_secret(secret: str, *, key: bytes) -> bytes:
    return encrypt(secret.encode("utf-8"), key=key)


def decrypt_secret(blob: bytes, *, key: bytes) -> str:
    return decrypt(blob, key=key).decode("utf-8")
