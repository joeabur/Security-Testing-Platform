import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.organization import Role
from app.schemas.fields import Email


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class OrganizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    role: Role  # the caller's own role in this organization


class MembershipInvite(BaseModel):
    email: Email
    role: Role = Role.VIEWER


class MembershipUpdate(BaseModel):
    role: Role


class MembershipRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    email: str
    full_name: str
    role: Role


class InvitationRead(BaseModel):
    """A pending invitation — no `Membership` exists yet, which is why this
    is a distinct shape from `MembershipRead` rather than one with a null
    `user_id`: a caller should not have to infer "pending" from an absence."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    role: Role
    expires_at: datetime
    created_at: datetime
    #: Whether the invitation email actually went out — `None` when this
    #: value isn't known for the row being read (every row returned by
    #: `GET .../invitations`, since the row itself carries no record of it).
    #: `invite_member`/`_create_invitation` set it explicitly, reflecting
    #: whether a platform SMTP relay was configured at the moment this
    #: specific invitation was created — the row persisting either way is
    #: what lets an admin later revoke and re-invite once mail is
    #: configured, rather than the invite silently vanishing.
    email_sent: bool | None = None


class InvitationAccept(BaseModel):
    token: str
