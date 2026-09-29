"""Backup codes for signing in when a TOTP authenticator device is lost.

Same secret-handling shape as `app/models/api_key.py` and
`app/models/password_reset.py`: the value shown to the person is 256 bits of
CSPRNG output split into a readable form, and only a SHA-256 digest is ever
stored. `POST /auth/2fa/enable` mints ten of these at once and shows them
exactly once, the same "shown once, digest kept" UX a reset link or an API
key's plaintext token already uses.
"""

import base64
import hashlib
import secrets
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.user import User

RECOVERY_CODE_COUNT = 10
_CODE_BYTES = 5  # 5 bytes -> 8 base32 chars, short enough to type by hand


def mint_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[tuple[str, str]]:
    """`count` fresh `(code, digest)` pairs. The caller stores the digests
    and shows the codes; nothing here keeps them."""
    codes: list[tuple[str, str]] = []
    for _ in range(count):
        code = base64.b32encode(secrets.token_bytes(_CODE_BYTES)).decode("ascii").rstrip("=")
        codes.append((code, digest_of(code)))
    return codes


def digest_of(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


class TotpRecoveryCode(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "totp_recovery_codes"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    code_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship()
