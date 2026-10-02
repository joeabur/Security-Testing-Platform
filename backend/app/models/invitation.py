"""An invitation to join an organization, for an email with no account yet.

`organizations.py`'s `invite_member` has always been able to add an
*existing* user to an organization directly — no token needed, since the
caller is already an account the platform can authenticate. This model is
for the other case: the invited email has no `User` row, so there is
nothing to grant a `Membership` to yet.

Same shape as `app/models/password_reset.py`'s `PasswordResetToken`, and
for the same reason: the value that goes in the invitation link is 256
bits of CSPRNG output, so only a SHA-256 digest is stored — the plaintext
token exists only in the email and the URL the recipient clicks. A row is
single-use (`used_at`) and short-lived (`expires_at`); unlike a password
reset, an organization admin can also explicitly revoke an unused
invitation before it expires (`revoked_at`), which is why this model has
two terminal-state columns where `PasswordResetToken` needed only one.
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.organization import Role

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.user import User

_TOKEN_BYTES = 32


def mint_invitation_token() -> tuple[str, str]:
    """A new `(token, digest)` pair. The caller stores the digest and emails
    the token; nothing here keeps it."""
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    return token, digest_of(token)


def digest_of(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class OrganizationInvitation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "organization_invitations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    #: The invited address, stored as given (lowercased at the API layer,
    #: same as everywhere else an email is matched in this codebase). Not a
    #: secret — needed to send the invitation and, on accept, to confirm the
    #: authenticated user redeeming the token is the person it was sent to.
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    role: Mapped[Role] = mapped_column(Enum(Role, name="role_enum"), nullable=False)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    invited_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped["Organization"] = relationship()
    invited_by: Mapped["User | None"] = relationship()

    def usable_at(self, now: datetime | None = None) -> bool:
        moment = now or datetime.now(UTC)
        return self.used_at is None and self.revoked_at is None and moment < self.expires_at
