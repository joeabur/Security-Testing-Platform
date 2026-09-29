"""Signing a generic webhook so a receiver can tell our POST from anyone's.

The scheme is the one most receivers already know how to verify: a timestamp
header, and an HMAC-SHA256 over `v1:<timestamp>:<body>` in hex. Two details
matter and are easy to get wrong:

* **The timestamp is inside the signed string.** Otherwise a captured request
  can be replayed forever; with it, a receiver can reject anything older than
  its tolerance and the signature still covers the age it is checking.
* **The signature covers the exact bytes sent.** Not a re-serialization of
  the payload — hence `RenderedMessage.body` being bytes all the way through.

Verification lives here too, and not only for tests: it is the reference a
customer's receiver is written against, and a scheme documented only in prose
gets implemented subtly differently on the other side.
"""

from __future__ import annotations

import hashlib
import hmac
import time

SIGNATURE_HEADER = "X-Kervy-Signature"
TIMESTAMP_HEADER = "X-Kervy-Timestamp"
EVENT_HEADER = "X-Kervy-Event"
SIGNATURE_VERSION = "v1"

#: How much clock skew a receiver should tolerate. Five minutes is the usual
#: figure; documented here so both sides use the same number.
DEFAULT_TOLERANCE_SECONDS = 300


def signing_string(timestamp: str, body: bytes) -> bytes:
    return b"%s:%s:%s" % (SIGNATURE_VERSION.encode(), timestamp.encode(), body)


def sign(secret: str, body: bytes, *, timestamp: str | None = None) -> tuple[str, str]:
    """Return `(timestamp, signature)` for these exact bytes."""
    stamp = timestamp or str(int(time.time()))
    digest = hmac.new(
        secret.encode("utf-8"), signing_string(stamp, body), hashlib.sha256
    ).hexdigest()
    return stamp, f"{SIGNATURE_VERSION}={digest}"


def verify(
    secret: str,
    body: bytes,
    *,
    timestamp: str,
    signature: str,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: float | None = None,
) -> bool:
    """Constant-time check, including the age of the timestamp."""
    try:
        stamp = int(timestamp)
    except (TypeError, ValueError):
        return False
    current = time.time() if now is None else now
    if abs(current - stamp) > tolerance_seconds:
        return False
    _, expected = sign(secret, body, timestamp=timestamp)
    return hmac.compare_digest(expected, signature)
