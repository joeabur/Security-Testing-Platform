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

    # Email.
    smtp_host: str | None = Field(default=None, max_length=255)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_username: str | None = Field(default=None, max_length=255)
    smtp_password_env_var: str | None = Field(default=None, max_length=128)
    from_address: str | None = Field(default=None, max_length=320)
    recipients: list[str] = Field(default_factory=list)

    # Jira Cloud only. `jira_site`/`jira_project_key` are constrained
    # because they end up in a request path or a project lookup — see
    # `app/core/integrations/policy.py`'s own note on this.
    jira_site: str | None = Field(default=None, max_length=63, pattern=r"^[a-z0-9-]+$")
    jira_email: str | None = Field(default=None, max_length=320)
    jira_api_token_env_var: str | None = Field(default=None, max_length=128)
    jira_project_key: str | None = Field(
        default=None, max_length=32, pattern=r"^[A-Z][A-Z0-9]{1,9}$"
    )
    jira_issue_type: str | None = Field(default=None, max_length=64)

    # ServiceNow only.
    servicenow_instance: str | None = Field(default=None, max_length=63, pattern=r"^[a-z0-9-]+$")
    servicenow_table: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9_]+$")
    servicenow_username: str | None = Field(default=None, max_length=255)
    servicenow_password_env_var: str | None = Field(default=None, max_length=128)

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
            self.jira_api_token_env_var,
            self.servicenow_password_env_var,
        ):
            if name is not None and not valid_env_var_name(name):
                raise ValueError(
                    f"{name!r} is not a valid environment variable name; a channel "
                    "references its secret by variable name, not by value"
                )

        ticket_fields = (
            self.jira_site,
            self.jira_email,
            self.jira_api_token_env_var,
            self.jira_project_key,
            self.jira_issue_type,
            self.servicenow_instance,
            self.servicenow_table,
            self.servicenow_username,
            self.servicenow_password_env_var,
        )

        if self.kind is ChannelKind.EMAIL_SMTP:
            if not self.smtp_host:
                raise ValueError("smtp_host is required for an email channel")
            if not self.from_address:
                raise ValueError("from_address is required for an email channel")
            if not self.recipients:
                raise ValueError("an email channel needs at least one recipient")
            if self.endpoint_env_var:
                raise ValueError("endpoint_env_var does not apply to an email channel")
            if any(ticket_fields):
                raise ValueError("ticketing fields do not apply to an email channel")
        elif self.kind is ChannelKind.TICKET_JIRA:
            if self.endpoint_env_var or self.signing_secret_env_var:
                raise ValueError(
                    "endpoint_env_var/signing_secret_env_var do not apply to a Jira channel; "
                    "it authenticates with an API token, not a signed webhook"
                )
            if self.smtp_host or self.recipients:
                raise ValueError("SMTP fields do not apply to a Jira channel")
            if self.servicenow_instance or self.servicenow_table:
                raise ValueError("ServiceNow fields do not apply to a Jira channel")
            missing = [
                field_name
                for field_name, value in (
                    ("jira_site", self.jira_site),
                    ("jira_email", self.jira_email),
                    ("jira_api_token_env_var", self.jira_api_token_env_var),
                    ("jira_project_key", self.jira_project_key),
                    ("jira_issue_type", self.jira_issue_type),
                )
                if not value
            ]
            if missing:
                raise ValueError(f"a Jira channel requires {', '.join(missing)}")
        elif self.kind is ChannelKind.TICKET_SERVICENOW:
            if self.endpoint_env_var or self.signing_secret_env_var:
                raise ValueError(
                    "endpoint_env_var/signing_secret_env_var do not apply to a ServiceNow "
                    "channel; it authenticates with a username and password, not a signed webhook"
                )
            if self.smtp_host or self.recipients:
                raise ValueError("SMTP fields do not apply to a ServiceNow channel")
            if self.jira_site or self.jira_project_key:
                raise ValueError("Jira fields do not apply to a ServiceNow channel")
            missing = [
                field_name
                for field_name, value in (
                    ("servicenow_instance", self.servicenow_instance),
                    ("servicenow_table", self.servicenow_table),
                    ("servicenow_username", self.servicenow_username),
                    ("servicenow_password_env_var", self.servicenow_password_env_var),
                )
                if not value
            ]
            if missing:
                raise ValueError(f"a ServiceNow channel requires {', '.join(missing)}")
        else:
            if not self.endpoint_env_var:
                raise ValueError(f"endpoint_env_var is required for a {self.kind.value} channel")
            if self.smtp_host or self.recipients:
                raise ValueError("SMTP fields do not apply to a webhook channel")
            if any(ticket_fields):
                raise ValueError("ticketing fields do not apply to a webhook channel")
            if self.kind is ChannelKind.GENERIC_WEBHOOK and not self.signing_secret_env_var:
                raise ValueError(
                    "signing_secret_env_var is required for a generic webhook: a receiver "
                    "that cannot verify a signature cannot tell our POST from anyone else's"
                )
            if self.kind is not ChannelKind.GENERIC_WEBHOOK and self.signing_secret_env_var:
                raise ValueError(
                    f"a {self.kind.value} channel is not signed; the vendor does not verify one"
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
    smtp_host: str | None
    smtp_port: int | None
    smtp_username: str | None
    from_address: str | None
    recipients: list[str] | None
    jira_site: str | None
    jira_email: str | None
    jira_api_token_env_var: str | None
    jira_project_key: str | None
    jira_issue_type: str | None
    servicenow_instance: str | None
    servicenow_table: str | None
    servicenow_username: str | None
    servicenow_password_env_var: str | None
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
    #: The ticket a `TICKET_*` channel's creation call returned. Null for
    #: every other kind.
    external_reference: str | None
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
