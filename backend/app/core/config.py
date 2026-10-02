import base64
import binascii
from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration, loaded from environment variables.

    No default is provided for secrets (JWT signing key, database credentials)
    in any non-local environment — the config loader must fail loudly rather
    than silently run with an insecure default in production.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: Literal["local", "ci", "staging", "production"] = "local"

    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/kervy",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    # --- AI layer (optional end to end) ------------------------------------
    # Absent means the whole assistant is off and every other part of the
    # platform behaves identically. `ai_api_key_env_var` is the NAME of an
    # environment variable; a key is never stored in configuration, the
    # database, or a log.
    ai_provider: str | None = Field(default=None, alias="AI_PROVIDER")
    ai_endpoint: str | None = Field(default=None, alias="AI_ENDPOINT")
    ai_model: str | None = Field(default=None, alias="AI_MODEL")
    ai_api_key_env_var: str | None = Field(default=None, alias="AI_API_KEY_ENV_VAR")
    ai_autonomy_mode: str = Field(default="ASSIST", alias="AI_AUTONOMY_MODE")
    # A ceiling on top of the $5.00 per-interaction budget
    # (app/core/assistant/egress.py's PROVIDER_BUDGETS), which is rebuilt
    # fresh on every call and so cannot by itself stop many small
    # interactions from adding up to an unbounded bill. This one is
    # enforced across calls, platform-wide, via a Redis counter that rolls
    # over daily (app/core/assistant/spend_cap.py).
    ai_daily_spend_cap_usd: float = Field(default=20.0, alias="AI_DAILY_SPEND_CAP_USD")

    jwt_secret: str = Field(default="insecure-local-dev-secret-change-me", alias="JWT_SECRET")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 12

    cors_allowed_origins: list[str] = Field(
        default=["http://localhost:3000"], alias="CORS_ALLOWED_ORIGINS"
    )

    # Where evidence bundles and their hash-chained manifests are written
    # (docs/BUILD_SPEC.md §13). A path, not a URL: evidence never leaves the
    # deployment by default, and there is no public download URL for it.
    evidence_root: str = Field(default="var/evidence", alias="EVIDENCE_ROOT")

    # --- plugins (docs/BUILD_SPEC.md §16) ---------------------------------
    # Off unless an operator points at a configuration file that names the
    # packages allowed to load. `pip install` must not be what decides which
    # code runs inside the scope engine's process. `KERVY_NO_PLUGINS=1` is the
    # `--no-plugins` switch: it wins over any configuration, so there is always
    # one thing to set when something has gone wrong.
    plugins_config: str | None = Field(default=None, alias="PLUGINS_CONFIG")
    no_plugins: bool = Field(default=False, alias="KERVY_NO_PLUGINS")

    # --- outbound integrations (docs/BUILD_SPEC.md §27) ------------------
    # Which hosts a notification may reach, beyond the vendor hosts pinned in
    # `app/core/integrations/contract.py`. This lives in the environment, not
    # in the database, on purpose: an organization admin may choose which
    # Slack workspace to notify, but adding a brand-new outbound destination
    # is an operator decision. A generic webhook whose host is not listed here
    # is refused, so the database alone can never widen egress.
    notify_allowed_webhook_hosts: list[str] = Field(
        default_factory=list, alias="KERVY_NOTIFY_ALLOWED_WEBHOOK_HOSTS"
    )
    notify_allowed_smtp_hosts: list[str] = Field(
        default_factory=list, alias="KERVY_NOTIFY_ALLOWED_SMTP_HOSTS"
    )
    # Which code hosts a connection may reach beyond github.com, whose API host
    # is pinned in code. A GitHub Enterprise install's host is site-specific, so
    # it takes an operator decision — held here, not in the database, for the
    # same reason as the webhook list above.
    vcs_allowed_hosts: list[str] = Field(default_factory=list, alias="KERVY_VCS_ALLOWED_HOSTS")

    # --- exploitation tier (Pentest module Phase 12) ----------------------
    # The specific nmap NSE script names an exploitation-fire request may
    # name, deployment-wide — never a whole category (exploit/brute/dos/
    # intrusive stay excluded in code regardless of this list). Empty by
    # default: a fresh deployment can fire nothing until an operator has
    # explicitly reviewed and named scripts here, the same secure-default
    # idiom as the webhook/VCS host allowlists above. This is one of three
    # independent gates a fire request must clear — the target's own
    # asset_scope.approved_modules and a live ExploitationAuthorization's
    # approved_script_names are the other two, and all three must agree.
    exploitation_allowed_nse_scripts: list[str] = Field(
        default_factory=list, alias="KERVY_EXPLOITATION_ALLOWED_NSE_SCRIPTS"
    )

    # Read by exactly one place — `backend/scripts/bootstrap_platform_owner.py`
    # — and never by any request-handling code. The script uses it once, to
    # find the *first* platform owner's already-registered account; every
    # owner after that is granted by an existing owner through
    # `POST /platform/owners` (app/api/v1/routers/platform.py), not by this
    # setting. Absent by default: a fresh deployment has no platform owner
    # until an operator deliberately runs the bootstrap script.
    platform_owner_bootstrap_email: str | None = Field(
        default=None, alias="KERVY_PLATFORM_OWNER_BOOTSTRAP_EMAIL"
    )

    # Base URL used to build links back into the platform in a notification.
    # Absent means notifications carry no link rather than a guessed one.
    public_base_url: str | None = Field(default=None, alias="KERVY_PUBLIC_BASE_URL")

    session_cookie_name: str = "kervy_session"
    session_cookie_secure: bool = Field(default=False, alias="SESSION_COOKIE_SECURE")

    # --- authentication rate limiting (§18, §22) ------------------------
    rate_limit_enabled: bool = Field(default=True, alias="KERVY_RATE_LIMIT_ENABLED")
    #: How many reverse proxies sit in front of this application. Zero — the
    #: default — means `X-Forwarded-For` is ignored entirely and the socket
    #: address is used. That default is load-bearing: trusting the header
    #: without a proxy in front lets any client mint a fresh rate-limit bucket
    #: per forged value, which is worse than no limiter because the control
    #: still looks enabled. See `app/core/ratelimit/keys.py`.
    trusted_proxy_count: int = Field(default=0, ge=0, le=8, alias="KERVY_TRUSTED_PROXY_COUNT")
    #: Pepper for identity bucket keys, so the counter store holds an HMAC
    #: rather than an email address. Defaults to the JWT secret because both
    #: are server-side secrets of the same lifetime and requiring a second one
    #: to be configured is how a deployment ends up with neither.
    rate_limit_pepper: str | None = Field(default=None, alias="KERVY_RATE_LIMIT_PEPPER")

    @property
    def effective_rate_limit_pepper(self) -> str:
        return self.rate_limit_pepper or self.jwt_secret

    # --- CSRF (§18, §22) ------------------------------------------------
    #: On by default. A control that ships off is a control nobody has, and
    #: the only callers it can inconvenience are cookie-authenticated browser
    #: sessions — API keys and Bearer tokens are unaffected by design.
    csrf_protection_enabled: bool = Field(default=True, alias="KERVY_CSRF_ENABLED")
    csrf_secret: str | None = Field(default=None, alias="KERVY_CSRF_SECRET")

    @property
    def effective_csrf_secret(self) -> str:
        """The key CSRF tokens are signed with.

        Defaults to the JWT secret for the same reason the rate-limit pepper
        does: both are server-side secrets with the same lifetime, and
        requiring a third one to be configured is how a deployment ends up
        with none of them set deliberately.
        """
        return self.csrf_secret or self.jwt_secret

    # --- evidence at rest (§13) -------------------------------------------
    #: Optional, per §13. Absent means a bundle is written exactly as it
    #: always was — the honestly-stated gap in `app/core/evidence/store.py`
    #: stays the default, not something silently half-solved. Present, it
    #: must be a base64-encoded 32-byte (AES-256) key, validated eagerly in
    #: `model_post_init` below rather than on first write, so a typo fails
    #: at startup instead of after a run has already collected evidence
    #: nobody can now get back onto disk.
    evidence_encryption_key: str | None = Field(default=None, alias="KERVY_EVIDENCE_ENCRYPTION_KEY")

    @property
    def evidence_encryption_key_bytes(self) -> bytes | None:
        if not self.evidence_encryption_key:
            return None
        try:
            key = base64.b64decode(self.evidence_encryption_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("KERVY_EVIDENCE_ENCRYPTION_KEY must be valid base64") from exc
        if len(key) != 32:
            raise ValueError(
                "KERVY_EVIDENCE_ENCRYPTION_KEY must decode to exactly 32 bytes "
                f"(AES-256); got {len(key)}"
            )
        return key

    # --- workflow automation (pentest-module Phase 8) ---------------------
    #: Unlike `evidence_encryption_key` above, this one is not "optional
    #: encryption" — a webhook secret must never sit in Postgres in
    #: cleartext. Absent means webhook automation cannot be enabled at all
    #: (`app/core/workflow/webhook_secret.py` refuses rather than storing one
    #: unencrypted); present, it is validated eagerly the same way.
    webhook_secret_encryption_key: str | None = Field(
        default=None, alias="KERVY_WEBHOOK_SECRET_ENCRYPTION_KEY"
    )

    @property
    def webhook_secret_encryption_key_bytes(self) -> bytes | None:
        if not self.webhook_secret_encryption_key:
            return None
        try:
            key = base64.b64decode(self.webhook_secret_encryption_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("KERVY_WEBHOOK_SECRET_ENCRYPTION_KEY must be valid base64") from exc
        if len(key) != 32:
            raise ValueError(
                "KERVY_WEBHOOK_SECRET_ENCRYPTION_KEY must decode to exactly 32 bytes "
                f"(AES-256); got {len(key)}"
            )
        return key

    # --- social OAuth login (Google, GitHub) -------------------------------
    # A provider is enabled only when both its client id and its client
    # secret's *env var name* are set — the same "absent means the whole
    # feature is off" shape as the AI layer above. The secret itself is never
    # a Settings field: it is read fresh from `os.environ` at call time
    # (`app/core/auth/oauth_providers.py`), the same indirection
    # `ai_api_key_env_var` uses, so it is never captured into this cached,
    # long-lived object.
    google_oauth_client_id: str | None = Field(default=None, alias="GOOGLE_OAUTH_CLIENT_ID")
    google_oauth_client_secret_env_var: str | None = Field(
        default=None, alias="GOOGLE_OAUTH_CLIENT_SECRET_ENV_VAR"
    )
    github_oauth_client_id: str | None = Field(default=None, alias="GITHUB_OAUTH_CLIENT_ID")
    github_oauth_client_secret_env_var: str | None = Field(
        default=None, alias="GITHUB_OAUTH_CLIENT_SECRET_ENV_VAR"
    )
    #: This backend's own externally-reachable origin, used to build the
    #: `redirect_uri` a provider sends the browser back to
    #: (`{oauth_callback_base_url}/api/v1/auth/oauth/{provider}/callback`).
    #: Deliberately separate from `public_base_url` above: that one is the
    #: *frontend's* origin (where a human ends up after the round trip);
    #: this one is the API's own, which is a different origin in every
    #: deployment this project documents.
    oauth_callback_base_url: str | None = Field(
        default=None, alias="KERVY_OAUTH_CALLBACK_BASE_URL"
    )

    # --- password reset -----------------------------------------------------
    password_reset_token_ttl_minutes: int = Field(
        default=30, alias="KERVY_PASSWORD_RESET_TOKEN_TTL_MINUTES"
    )
    #: The platform's own outbound mail relay, for a reset link — distinct
    #: from `app/core/integrations/send.py`'s `send_email`, which is bound to
    #: a per-organization `NotificationChannel` destination an admin
    #: configured. A password reset has no organization in scope yet (the
    #: caller has only proven they can read an inbox), so it needs one fixed,
    #: operator-configured relay instead. Absent means the feature is
    #: disabled: `POST /auth/forgot-password` still returns its
    #: non-enumerating 202 (so the endpoint's existence never leaks whether
    #: reset is configured), but no mail is sent and no token is issued.
    platform_smtp_host: str | None = Field(default=None, alias="KERVY_PLATFORM_SMTP_HOST")
    platform_smtp_port: int = Field(default=587, alias="KERVY_PLATFORM_SMTP_PORT")
    platform_smtp_from_address: str | None = Field(
        default=None, alias="KERVY_PLATFORM_SMTP_FROM_ADDRESS"
    )
    platform_smtp_username: str | None = Field(default=None, alias="KERVY_PLATFORM_SMTP_USERNAME")
    #: Name of the env var holding the SMTP password, not the value — same
    #: indirection as the OAuth client secrets above.
    platform_smtp_password_env_var: str | None = Field(
        default=None, alias="KERVY_PLATFORM_SMTP_PASSWORD_ENV_VAR"
    )

    # --- two-factor authentication (TOTP) ----------------------------------
    #: Not "optional encryption" any more than `webhook_secret_encryption_key`
    #: is — a TOTP shared secret is exactly as sensitive as a webhook secret
    #: (either lets someone impersonate the account it belongs to), so it
    #: must never sit in Postgres in cleartext. Absent means `POST
    #: /auth/2fa/setup` refuses rather than storing one unencrypted; present,
    #: validated eagerly the same way as the other AES-256 keys on this class.
    totp_encryption_key: str | None = Field(default=None, alias="KERVY_TOTP_ENCRYPTION_KEY")

    @property
    def totp_encryption_key_bytes(self) -> bytes | None:
        if not self.totp_encryption_key:
            return None
        try:
            key = base64.b64decode(self.totp_encryption_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("KERVY_TOTP_ENCRYPTION_KEY must be valid base64") from exc
        if len(key) != 32:
            raise ValueError(
                f"KERVY_TOTP_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256); "
                f"got {len(key)}"
            )
        return key

    @property
    def totp_enabled_platform_wide(self) -> bool:
        return self.totp_encryption_key_bytes is not None

    @property
    def google_oauth_enabled(self) -> bool:
        return bool(self.google_oauth_client_id and self.google_oauth_client_secret_env_var)

    @property
    def github_oauth_enabled(self) -> bool:
        return bool(self.github_oauth_client_id and self.github_oauth_client_secret_env_var)

    @property
    def password_reset_enabled(self) -> bool:
        return bool(self.platform_smtp_host and self.platform_smtp_from_address)

    def model_post_init(self, __context: object) -> None:
        if (
            self.environment == "production"
            and self.jwt_secret == "insecure-local-dev-secret-change-me"
        ):
            raise ValueError(
                "JWT_SECRET must be set explicitly when ENVIRONMENT=production; "
                "refusing to start with the local development default."
            )
        # Accessed for its side effect: raises now, at startup, rather than
        # on the first evidence write during a run.
        _ = self.evidence_encryption_key_bytes
        _ = self.webhook_secret_encryption_key_bytes
        _ = self.totp_encryption_key_bytes


@lru_cache
def get_settings() -> Settings:
    return Settings()
