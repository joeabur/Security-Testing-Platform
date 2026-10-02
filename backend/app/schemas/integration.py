"""Notification channel request/response shapes (docs/BUILD_SPEC.md §27).

`ChannelRead` carries `endpoint_env_var` and `endpoint_redacted` and never an
endpoint URL or a secret, because there is no endpoint that returns one. That
is not an oversight to be fixed later: the value is not in the database to
return.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.integrations.contract import ChannelKind, EventType
from app.core.integrations.policy import valid_env_var_name
from app.core.probes.models import Severity


class ChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: ChannelKind
    events: list[EventType] = Field(min_length=1)
    min_severity: Severity | None = None
    enabled: bool = True

    # Webhook kinds. The variable *name*; the value stays in the environment.
    endpoint_env_var: str | None = Field(default=None, max_length=128)
    signing_secret_env_var: str | None = Field(default=None, max_length=128)

    # Splunk HEC only.
    auth_token_env_var: str | None = Field(default=None, max_length=128)

    # Sentinel only. None of these six are secrets except
    # azure_client_secret_env_var — see app/models/integration.py.
    #
    # All four identifier fields below end up interpolated into the path of
    # an outbound HTTPS request (`send.py`'s token-exchange and
    # Logs-Ingestion URLs). The destination *host* in those requests is
    # always a fixed literal or an already-policy-checked `Destination`, so
    # these values can never redirect the request to a different host — but
    # an unconstrained value could still rewrite the *path* (e.g. embed
    # `/../` or a stray `?`/`#`) in a way static analysis cannot distinguish
    # from a host-changing injection. Restricting the charset to what Azure
    # itself ever issues for these identifiers closes that off at the one
    # place it can be fixed for good, rather than trusting every call site
    # downstream to escape it correctly.
    sentinel_endpoint: str | None = Field(default=None, max_length=300)
    azure_tenant_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    azure_client_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9-]+$")
    azure_client_secret_env_var: str | None = Field(default=None, max_length=128)
    sentinel_dcr_immutable_id: str | None = Field(
        default=None, max_length=64, pattern=r"^[A-Za-z0-9-]+$"
    )
    sentinel_stream_name: str | None = Field(
        default=None, max_length=100, pattern=r"^[A-Za-z0-9_-]+$"
    )

    # Email.
    smtp_host: str | None = Field(default=None, max_length=255)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_username: str | None = Field(default=None, max_length=255)
    smtp_password_env_var: str | None = Field(default=None, max_length=128)
    from_address: str | None = Field(default=None, max_length=320)
    recipients: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_kind_fields(self) -> "ChannelCreate":
        """Reject a channel that could never deliver, at creation time.

        A channel that fails only on its first real event is a channel nobody
        finds out about until the incident it was supposed to announce.
        """
        for name in (
            self.endpoint_env_var,
            self.signing_secret_env_var,
            self.smtp_password_env_var,
            self.auth_token_env_var,
            self.azure_client_secret_env_var,
        ):
            if name is not None and not valid_env_var_name(name):
                raise ValueError(
                    f"{name!r} is not a valid environment variable name; a channel "
                    "references its secret by variable name, not by value"
                )

        signed_kinds = (ChannelKind.GENERIC_WEBHOOK, ChannelKind.SIEM_GENERIC_CEF)

        if self.kind is ChannelKind.EMAIL_SMTP:
            if not self.smtp_host:
                raise ValueError("smtp_host is required for an email channel")
            if not self.from_address:
                raise ValueError("from_address is required for an email channel")
            if not self.recipients:
                raise ValueError("an email channel needs at least one recipient")
            if self.endpoint_env_var:
                raise ValueError("endpoint_env_var does not apply to an email channel")
        elif self.kind is ChannelKind.SIEM_SENTINEL:
            if self.endpoint_env_var or self.signing_secret_env_var or self.auth_token_env_var:
                raise ValueError(
                    "endpoint_env_var/signing_secret_env_var/auth_token_env_var do not apply "
                    "to a Sentinel channel; it authenticates with an Entra ID app registration"
                )
            if self.smtp_host or self.recipients:
                raise ValueError("SMTP fields do not apply to a Sentinel channel")
            missing = [
                field_name
                for field_name, value in (
                    ("sentinel_endpoint", self.sentinel_endpoint),
                    ("azure_tenant_id", self.azure_tenant_id),
                    ("azure_client_id", self.azure_client_id),
                    ("azure_client_secret_env_var", self.azure_client_secret_env_var),
                    ("sentinel_dcr_immutable_id", self.sentinel_dcr_immutable_id),
                    ("sentinel_stream_name", self.sentinel_stream_name),
                )
                if not value
            ]
            if missing:
                raise ValueError(f"a Sentinel channel requires {', '.join(missing)}")
        else:
            if not self.endpoint_env_var:
                raise ValueError(f"endpoint_env_var is required for a {self.kind.value} channel")
            if self.smtp_host or self.recipients:
                raise ValueError("SMTP fields do not apply to a webhook channel")
            if (
                self.azure_tenant_id
                or self.azure_client_id
                or self.azure_client_secret_env_var
                or self.sentinel_endpoint
            ):
                raise ValueError("Sentinel fields do not apply to a non-Sentinel channel")
            if self.kind in signed_kinds and not self.signing_secret_env_var:
                raise ValueError(
                    f"signing_secret_env_var is required for a {self.kind.value} channel: a "
                    "receiver that cannot verify a signature cannot tell our POST from "
                    "anyone else's"
                )
            if self.kind not in signed_kinds and self.signing_secret_env_var:
                raise ValueError(
                    f"a {self.kind.value} channel is not signed; the vendor does not verify one"
                )
            if self.kind is ChannelKind.SIEM_SPLUNK_HEC and not self.auth_token_env_var:
                raise ValueError(
                    "auth_token_env_var is required for a Splunk HEC channel: the collector "
                    "refuses any request with no Authorization header"
                )
            if self.kind is not ChannelKind.SIEM_SPLUNK_HEC and self.auth_token_env_var:
                raise ValueError(
                    f"auth_token_env_var does not apply to a {self.kind.value} channel"
                )
        return self


class ChannelUpdate(BaseModel):
    """Only the fields it is safe to change in place.

    Not the kind and not the endpoint: changing where a channel points is
    creating a different channel, and doing it in place would leave the
    delivery history attached to a destination it never reached.
    """

    events: list[EventType] | None = Field(default=None, min_length=1)
    min_severity: Severity | None = None
    enabled: bool | None = None
    recipients: list[str] | None = None


class ChannelRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: str
    events: list[str]
    min_severity: str | None
    enabled: bool
    endpoint_env_var: str | None
    #: Scheme, host and path shape. Never the token-bearing path itself.
    endpoint_redacted: str | None
    signing_secret_env_var: str | None
    auth_token_env_var: str | None
    sentinel_endpoint: str | None
    azure_tenant_id: str | None
    azure_client_id: str | None
    azure_client_secret_env_var: str | None
    sentinel_dcr_immutable_id: str | None
    sentinel_stream_name: str | None
    smtp_host: str | None
    smtp_port: int | None
    smtp_username: str | None
    from_address: str | None
    recipients: list[str] | None
    created_at: datetime


class DeliveryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    channel_id: uuid.UUID
    event_type: str
    resource_type: str | None
    resource_id: str | None
    status: str
    attempts: int
    status_code: int | None
    last_error: str | None
    next_attempt_at: datetime | None
    delivered_at: datetime | None
    created_at: datetime


class ChannelTestResult(BaseModel):
    """Outcome of a deliberate test delivery.

    `detail` is the already-redacted delivery detail, so an operator can see
    *why* a channel is broken without the response body or the URL.
    """

    delivered: bool
    status_code: int | None
    detail: str
    delivery_id: uuid.UUID | None
