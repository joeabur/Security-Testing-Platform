"""Organization-scoped API keys for CI/CD (docs/BUILD_SPEC.md §17.4).

Three decisions are worth stating, because each of them is the kind of thing
that is hard to change later.

**The secret is shown once and stored as a digest.** §17.4 requires it, and
the digest is SHA-256 rather than Argon2 on purpose: the secret is 256 bits
of CSPRNG output, so there is nothing to brute-force, and a deliberately slow
KDF on every CI request would buy latency and no security. A password is the
opposite case, which is why `app/auth/security.py` uses Argon2id for those.

**A key's authority is its scopes, and the role is derived from them.** One
source of truth. Carrying both a scope list and a role would let the two
disagree, and then no one can say which the platform enforces.

**A key can never reach an admin action.** The highest role any scope maps to
is security engineer, so a CI key cannot create a target, grant
authorization, add a member, or mint another key. That is deliberate: the
authorization grant is the human act this whole platform is built around, and
a credential living in a CI runner must not be able to perform it.
"""

import enum
import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.organization import Role

if TYPE_CHECKING:
    from app.models.organization import Organization


# What a key may be used for. A closed set: an unknown scope string is
# rejected at creation rather than silently ignored, because a scope nobody
# enforces reads like a restriction that is not there.
class ApiKeyScope(enum.StrEnum):
    READ = "read"
    SCAN = "scan"
    TRIAGE = "triage"


# The single mapping from scope to authority. Capped at security engineer:
# see the module docstring.
_SCOPE_ROLES: dict[ApiKeyScope, Role] = {
    ApiKeyScope.READ: Role.VIEWER,
    ApiKeyScope.TRIAGE: Role.ANALYST,
    ApiKeyScope.SCAN: Role.SECURITY_ENGINEER,
}

# Keys are recognisable on sight so a leaked one can be grepped for, and the
# id travels in the token so verification is one indexed lookup plus one
# constant-time compare rather than a scan of every row.
TOKEN_PREFIX = "kervy_"
_ID_BYTES = 8
_SECRET_BYTES = 32


def role_for_scopes(scopes: list[str] | tuple[str, ...]) -> Role:
    """The most privileged role the scopes grant, defaulting to viewer."""
    roles = [_SCOPE_ROLES[ApiKeyScope(scope)] for scope in scopes]
    if not roles:
        return Role.VIEWER
    return min(roles, key=lambda role: Role.seniority_order().index(role))


def mint_token() -> tuple[str, str, str]:
    """A new token: `(token, key_id, digest)`.

    The caller stores the id and the digest and returns the token to the
    person once. Nothing here keeps the token.
    """
    key_id = secrets.token_hex(_ID_BYTES)
    secret = secrets.token_urlsafe(_SECRET_BYTES)
    return (f"{TOKEN_PREFIX}{key_id}_{secret}", key_id, digest_of(secret))


def digest_of(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def split_token(token: str) -> tuple[str, str] | None:
    """`(key_id, secret)` from a presented token, or `None` if malformed.

    Parsed strictly. A token that does not have this exact shape is not a key
    this platform issued, and guessing at it would only widen what the
    verification path has to tolerate.
    """
    if not token.startswith(TOKEN_PREFIX):
        return None
    body = token[len(TOKEN_PREFIX) :]
    key_id, separator, secret = body.partition("_")
    if not separator or len(key_id) != _ID_BYTES * 2 or not secret:
        return None
    try:
        int(key_id, 16)
    except ValueError:
        return None
    return (key_id, secret)


class ApiKey(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "api_keys"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    key_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    scopes: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Nullable means "does not expire", which an operator has to choose
    # explicitly rather than getting by leaving a field blank.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped["Organization"] = relationship()

    @property
    def role(self) -> Role:
        return role_for_scopes([str(scope) for scope in (self.scopes or [])])

    def matches(self, secret: str) -> bool:
        """Constant-time comparison, so a wrong key cannot be narrowed down by
        timing the response."""
        return hmac.compare_digest(self.token_digest, digest_of(secret))

    def usable_at(self, now: datetime | None = None) -> bool:
        moment = now or datetime.now(UTC)
        if self.revoked_at is not None:
            return False
        return self.expires_at is None or moment < self.expires_at
