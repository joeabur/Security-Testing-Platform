"""One row per (provider, external subject) a user has linked.

**Identity is `(provider, provider_user_id)`, never email.** Email is stored
alongside for the audit trail an admin might read, but nothing here or in
`app/api/v1/routers/auth.py`'s callback handler matches an incoming OAuth
profile against an existing account by email address. Doing that would let
whichever party controls an email address at the *provider* silently attach
itself to a local account by that same address — a provider that does not
itself verify email ownership turns "sign in with Google" into "sign in as
anyone whose address you can type in a form". Because of that, a callback
whose email matches an existing password-only `User` row refuses (409) the
same way `POST /auth/register` already refuses a duplicate email today,
rather than linking silently.
"""

import enum
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.user import User


class OAuthProvider(enum.StrEnum):
    GOOGLE = "google"
    GITHUB = "github"


class OAuthIdentity(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "oauth_identities"
    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_oauth_identity_subject"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(20), nullable=False)
    #: The provider's own stable subject id (Google's `sub`, GitHub's numeric
    #: user id as a string) — never the email, see the module docstring.
    provider_user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    #: What the provider reported at link time. Informational only; not
    #: re-checked on later logins and never used to find this row.
    email_at_link: Mapped[str] = mapped_column(String(320), nullable=False)

    user: Mapped["User"] = relationship()
