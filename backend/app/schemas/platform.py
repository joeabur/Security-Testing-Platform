import uuid

from pydantic import BaseModel

from app.models.user import PlatformRole
from app.schemas.fields import Email


class PlatformOwnerGrant(BaseModel):
    email: Email


class PlatformOwnerRead(BaseModel):
    """`User.id` is read back as `user_id` here, not `id` — a platform owner
    is a fact about a user, not a resource with its own identity or its own
    lifecycle timestamp; when the grant happened is in the audit log
    (`action="platform_owner.grant"`), not duplicated onto this row.
    Built explicitly from a `User` in the router rather than via
    `from_attributes`, since the field names deliberately don't match.
    """

    user_id: uuid.UUID
    email: str
    full_name: str
    platform_role: PlatformRole
