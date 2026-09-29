from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.organization import Membership


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    #: Null for an account created via OAuth that has never also set a local
    #: password. `verify_password` is never called with a null hash — every
    #: caller (`/auth/login`, `/auth/reset-password`) checks for `None` first
    #: and refuses or treats it as "no password set" rather than passing it
    #: to Argon2.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: A JWT issued before this moment is rejected, however long its own
    #: `exp` still has to run (app/core/revocation/). Null means nothing has
    #: ever been revoked in bulk for this user. Durable in Postgres rather
    #: than Redis on purpose: the per-token deny-list is cheap to lose on a
    #: Redis restart (a logged-out token becomes valid again for at most its
    #: own remaining lifetime), but losing a "log out everywhere" cutover the
    #: same way would silently undo a compromise response — the one case this
    #: column exists for.
    tokens_valid_after: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    memberships: Mapped[list["Membership"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
