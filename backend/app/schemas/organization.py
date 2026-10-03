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


class InvitationAccept(BaseModel):
    token: str
