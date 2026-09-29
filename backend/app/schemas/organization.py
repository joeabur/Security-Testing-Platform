import uuid

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
