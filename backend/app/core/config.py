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
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/aegis",
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
    # code runs inside the scope engine's process. `AEGIS_NO_PLUGINS=1` is the
    # `--no-plugins` switch: it wins over any configuration, so there is always
    # one thing to set when something has gone wrong.
    plugins_config: str | None = Field(default=None, alias="PLUGINS_CONFIG")
    no_plugins: bool = Field(default=False, alias="AEGIS_NO_PLUGINS")

    # --- outbound integrations (docs/BUILD_SPEC.md §27) ------------------
    # Which hosts a notification may reach, beyond the vendor hosts pinned in
    # `app/core/integrations/contract.py`. This lives in the environment, not
    # in the database, on purpose: an organization admin may choose which
    # Slack workspace to notify, but adding a brand-new outbound destination
    # is an operator decision. A generic webhook whose host is not listed here
    # is refused, so the database alone can never widen egress.
    notify_allowed_webhook_hosts: list[str] = Field(
        default_factory=list, alias="AEGIS_NOTIFY_ALLOWED_WEBHOOK_HOSTS"
    )
    notify_allowed_smtp_hosts: list[str] = Field(
        default_factory=list, alias="AEGIS_NOTIFY_ALLOWED_SMTP_HOSTS"
    )
    # Which code hosts a connection may reach beyond github.com, whose API host
    # is pinned in code. A GitHub Enterprise install's host is site-specific, so
    # it takes an operator decision — held here, not in the database, for the
    # same reason as the webhook list above.
    vcs_allowed_hosts: list[str] = Field(default_factory=list, alias="AEGIS_VCS_ALLOWED_HOSTS")

    # Base URL used to build links back into the platform in a notification.
    # Absent means notifications carry no link rather than a guessed one.
    public_base_url: str | None = Field(default=None, alias="AEGIS_PUBLIC_BASE_URL")

    session_cookie_name: str = "aegis_session"
    session_cookie_secure: bool = Field(default=False, alias="SESSION_COOKIE_SECURE")

    # --- authentication rate limiting (§18, §22) ------------------------
    rate_limit_enabled: bool = Field(default=True, alias="AEGIS_RATE_LIMIT_ENABLED")
    #: How many reverse proxies sit in front of this application. Zero — the
    #: default — means `X-Forwarded-For` is ignored entirely and the socket
    #: address is used. That default is load-bearing: trusting the header
    #: without a proxy in front lets any client mint a fresh rate-limit bucket
    #: per forged value, which is worse than no limiter because the control
    #: still looks enabled. See `app/core/ratelimit/keys.py`.
    trusted_proxy_count: int = Field(default=0, ge=0, le=8, alias="AEGIS_TRUSTED_PROXY_COUNT")
    #: Pepper for identity bucket keys, so the counter store holds an HMAC
    #: rather than an email address. Defaults to the JWT secret because both
    #: are server-side secrets of the same lifetime and requiring a second one
    #: to be configured is how a deployment ends up with neither.
    rate_limit_pepper: str | None = Field(default=None, alias="AEGIS_RATE_LIMIT_PEPPER")

    @property
    def effective_rate_limit_pepper(self) -> str:
        return self.rate_limit_pepper or self.jwt_secret

    # --- CSRF (§18, §22) ------------------------------------------------
    #: On by default. A control that ships off is a control nobody has, and
    #: the only callers it can inconvenience are cookie-authenticated browser
    #: sessions — API keys and Bearer tokens are unaffected by design.
    csrf_protection_enabled: bool = Field(default=True, alias="AEGIS_CSRF_ENABLED")
    csrf_secret: str | None = Field(default=None, alias="AEGIS_CSRF_SECRET")

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
    evidence_encryption_key: str | None = Field(default=None, alias="AEGIS_EVIDENCE_ENCRYPTION_KEY")

    @property
    def evidence_encryption_key_bytes(self) -> bytes | None:
        if not self.evidence_encryption_key:
            return None
        try:
            key = base64.b64decode(self.evidence_encryption_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("AEGIS_EVIDENCE_ENCRYPTION_KEY must be valid base64") from exc
        if len(key) != 32:
            raise ValueError(
                "AEGIS_EVIDENCE_ENCRYPTION_KEY must decode to exactly 32 bytes "
                f"(AES-256); got {len(key)}"
            )
        return key

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
