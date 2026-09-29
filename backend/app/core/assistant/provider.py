"""AI provider abstraction (Implementation Specification §9).

Small on purpose. The requirement is two capabilities — `generate` and
`structured_output` — behind an interface that does not name a vendor, not
an agent framework.

Three rules shape it:

* **No vendor lock-in.** Anything speaking the OpenAI-compatible chat
  completions shape works, including a locally-hosted model, which is what
  makes it possible to run this against a client's data without sending that
  data anywhere.
* **Credentials by reference.** The configuration holds the *name* of an
  environment variable, resolved in the worker, exactly as target
  credentials are handled (§2). A key never reaches the database, a log, or
  a report.
* **The provider is not a target.** Its endpoint is infrastructure the
  operator configured. The call still goes through the one gated transport,
  under a scope that allows the provider host and nothing else — see
  `platform_egress_context`.
"""

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_MAX_TOKENS = 1024


class ProviderError(RuntimeError):
    """The provider could not be reached, or returned something unusable."""


class ProviderNotConfiguredError(ProviderError):
    """No AI provider is configured. The platform works without one."""


@dataclass(frozen=True)
class ProviderConfig:
    """How to reach a model. Note the absence of an api_key field."""

    provider: str
    endpoint: str
    model: str
    # The NAME of an environment variable, never a key.
    api_key_env_var: str | None = None
    # CIDR strings the operator explicitly authorized this provider's own
    # endpoint to resolve to, if it is a private/loopback address — see
    # `platform_egress_context` below. Empty means only a public address is
    # reachable, matching `RulesOfEngagement.allowed_ip_ranges`'s own
    # default-deny posture.
    allowed_ip_ranges: tuple[str, ...] = ()
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_output_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = 0.0
    # An optional ceiling an operator sets per assessment. Enforced by the
    # service, which counts what it spends.
    max_cost_usd: float | None = None

    @property
    def host(self) -> str:
        return urlsplit(self.endpoint).hostname or ""

    def resolve_key(self, environ: Mapping[str, str] | None = None) -> str | None:
        if not self.api_key_env_var:
            return None
        source = os.environ if environ is None else environ
        return source.get(self.api_key_env_var) or None


@dataclass(frozen=True)
class Completion:
    """What a provider returned, plus what it cost."""

    text: str
    model: str
    tokens_sent: int = 0
    tokens_received: int = 0
    # Present only when the provider reports it; never estimated and
    # presented as measured.
    cost_usd: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class AIProvider(Protocol):
    """The whole provider surface. Two methods, deliberately."""

    name: str
    model: str

    async def generate(self, prompt: str, *, system: str | None = None) -> Completion: ...

    async def structured_output(
        self, prompt: str, *, schema: dict[str, Any], system: str | None = None
    ) -> tuple[dict[str, Any], Completion]:
        """Return parsed JSON matching `schema`, plus the raw completion.

        A model that returns unparseable output raises rather than being
        repaired: silently "fixing" a malformed response is how invented
        content enters a pipeline that is supposed to be evidence-led.
        """
        ...


def parse_structured(text: str, schema: dict[str, Any]) -> dict[str, Any]:
    """Parse a model's JSON reply and check its required keys.

    Tolerates a fenced code block, because models emit them constantly, but
    does not attempt to repair malformed JSON or invent a missing key.
    """
    candidate = text.strip()
    if candidate.startswith("```"):
        lines = [line for line in candidate.splitlines() if not line.strip().startswith("```")]
        candidate = "\n".join(lines).strip()

    try:
        parsed = json.loads(candidate)
    except ValueError as exc:
        raise ProviderError(
            f"provider did not return valid JSON: {exc}. The response is discarded "
            "rather than repaired, so nothing invented reaches a draft."
        ) from exc

    if not isinstance(parsed, dict):
        raise ProviderError("provider returned JSON that is not an object")

    missing = [key for key in schema.get("required", []) if key not in parsed]
    if missing:
        raise ProviderError(f"provider response is missing required field(s): {', '.join(missing)}")
    return parsed
