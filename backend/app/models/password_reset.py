"""A one-time, short-lived credential for `POST /auth/reset-password`.

Same shape as `app/models/api_key.py`'s secret handling, and for the same
reason: the value that goes in the reset link is 256 bits of CSPRNG output,
so there is nothing to brute-force and a slow KDF buys nothing — only a
SHA-256 digest is stored, the plaintext token exists only in the email and
the URL the recipient clicks.

A row is single-use (`used_at`) and short-lived (`expires_at`), and issuing a
new one does not invalidate an older unused one by itself — `service.py`'s
`request_password_reset` deletes any of the user's existing unused rows
first, so at most one reset link is ever live, which matches "the link in
your most recent email is the one that works."
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.user import User

_TOKEN_BYTES = 32


def mint_reset_token() -> tuple[str, str]:
    """A new `(token, digest)` pair. The caller stores the digest and emails
    the token; nothing here keeps it."""
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    return token, digest_of(token)


def digest_of(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class PasswordResetToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "password_reset_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship()

    def usable_at(self, now: datetime | None = None) -> bool:
        moment = now or datetime.now(UTC)
        return self.used_at is None and moment < self.expires_at
