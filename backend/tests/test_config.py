"""`KERVY_EVIDENCE_ENCRYPTION_KEY` validation (docs/BUILD_SPEC.md §13).

A misconfigured key must fail at startup, not on the first evidence write
during a run — by then a probe's observation is already gone if the write
is refused. `Settings` is instantiated directly here rather than through the
cached `get_settings()` singleton, since these tests are about construction
itself failing or succeeding.
"""

import base64

import pytest

from app.core.config import Settings


def test_no_key_means_no_encryption() -> None:
    settings = Settings(JWT_SECRET="s")  # pragma: allowlist secret
    assert settings.evidence_encryption_key_bytes is None


def test_a_valid_32_byte_key_decodes() -> None:
    key = base64.b64encode(b"\x00" * 32).decode()
    settings = Settings(
        JWT_SECRET="s",  # pragma: allowlist secret
        KERVY_EVIDENCE_ENCRYPTION_KEY=key,
    )
    assert settings.evidence_encryption_key_bytes == b"\x00" * 32


def test_a_non_base64_key_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match="valid base64"):
        Settings(
            JWT_SECRET="s",  # pragma: allowlist secret
            KERVY_EVIDENCE_ENCRYPTION_KEY="not base64 at all!!",
        )


def test_a_wrong_length_key_is_refused_at_construction() -> None:
    """16 bytes is a valid, real AES key length — just the wrong one for
    AES-256. Accepting it silently would mean the operator finds out only if
    they went looking for what algorithm was actually in use."""
    short_key = base64.b64encode(b"\x00" * 16).decode()
    with pytest.raises(ValueError, match="32 bytes"):
        Settings(
            JWT_SECRET="s",  # pragma: allowlist secret
            KERVY_EVIDENCE_ENCRYPTION_KEY=short_key,
        )
