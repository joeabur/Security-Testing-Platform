import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.fields import Email


class RegisterRequest(BaseModel):
    email: Email
    full_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=12, max_length=200)


class LoginRequest(BaseModel):
    email: Email
    password: str


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserRead


class SessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    expires_at: datetime
    ip_address: str | None
    user_agent: str | None
    is_current: bool


class OAuthProvidersRead(BaseModel):
    """Which social-login buttons the frontend should render. A provider
    absent here (both false) is not merely unconfigured — hitting its
    authorize/callback routes directly still 404s, the same way a route
    behind any other disabled feature does."""

    google: bool
    github: bool


class ForgotPasswordRequest(BaseModel):
    email: Email


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=12, max_length=200)
