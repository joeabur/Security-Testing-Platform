import enum
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.organization import Membership


class PlatformRole(enum.StrEnum):
    """Authority above every organization's own `Role.OWNER` — a platform
    owner manages the deployment itself (other platform owners, platform-wide
    integration defaults, and anything else no single organization is the
    right scope for), not any one organization's data.

    Deliberately a single member today. The hierarchy this models (per
    docs/roadmap.md's platform-owner write-up) allows a lower platform
    "administrator" tier later without a schema change — this column stays
    nullable and this enum only grows — but nothing issues one yet, so it is
    not named here until something actually distinguishes it from OWNER.
    """

    OWNER = "owner"


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
    #: AES-256-GCM ciphertext of the TOTP shared secret (nonce-prefixed, same
    #: shape `app/core/evidence/crypto.py::encrypt` produces), or null. Set by
    #: `POST /auth/2fa/setup` before enrollment is confirmed, so a caller who
    #: never finishes enrolling leaves an unused secret sitting here — harmless,
    #: since login only ever checks `totp_enabled`, never whether this column is
    #: populated.
    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    #: The only column `/auth/login` actually reads to decide whether a second
    #: factor is required. Flips to `True` only after `POST /auth/2fa/enable`
    #: verifies a real code against the stored secret — never at `setup` time.
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Null for every ordinary user — platform authority is opt-in, never
    #: inferred from an organization role. Set only by `backend/scripts/
    #: bootstrap_platform_owner.py` (once, at deployment setup) or by an
    #: existing platform owner granting another through `POST
    #: /platform/owners` (app/api/v1/routers/platform.py). Never derived
    #: from `email` at request time — see that router's module docstring
    #: for why a hard-coded address in authorization logic is exactly the
    #: bug this column exists to avoid.
    platform_role: Mapped[PlatformRole | None] = mapped_column(
        Enum(PlatformRole, name="platform_role_enum"), nullable=True
    )

    memberships: Mapped[list["Membership"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
