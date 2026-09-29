"""The guard rails every lab service runs behind (docs/BUILD_SPEC.md §2.4).

Five requirements, and each one is enforced here rather than described in a
README, because a README does not stop a process from starting:

* bind to loopback by default,
* refuse to start if a real provider API key is in the environment,
* use a local stub model — never a provider,
* contain only synthetic data,
* print a banner identifying itself as intentionally vulnerable.

The API-key check is the one worth dwelling on. This app is built to leak its
system prompt, follow injected instructions and render model output as raw
HTML. If it were pointed at a real model with a real key, a prompt-injection
demo would become a bill, or a data-exfiltration path into somebody's actual
account. So the presence of a key is treated as a configuration error and the
service refuses to start.
"""

import os
import sys

BANNER = r"""
+--------------------------------------------------------------------------+
|                                                                          |
|   KERVY DEMO TARGET — INTENTIONALLY VULNERABLE                           |
|                                                                          |
|   This service is built to be exploited. It leaks its system prompt,     |
|   follows injected instructions, renders model output as raw HTML, and   |
|   serves one tenant's records to another.                                |
|                                                                          |
|   Do not deploy it. Do not expose it. Do not put real data in it.        |
|   Everything it contains is synthetic (*.invalid, AKIAEXAMPLE...).       |
|                                                                          |
+--------------------------------------------------------------------------+
"""

# Environment variables that name a real provider credential. Their *presence*
# is the problem, whatever the value: a lab that talks to a real model is no
# longer a lab.
PROVIDER_KEY_VARS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "COHERE_API_KEY",
    "MISTRAL_API_KEY",
    "HUGGINGFACEHUB_API_TOKEN",
    "HF_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
    "REPLICATE_API_TOKEN",
    "TOGETHER_API_KEY",
    "GROQ_API_KEY",
)

DEFAULT_HOST = "127.0.0.1"


class LabRefusedToStart(RuntimeError):
    """The lab will not run in this environment."""


def provider_keys_present(environ: dict[str, str] | None = None) -> list[str]:
    source = os.environ if environ is None else environ
    return sorted(name for name in PROVIDER_KEY_VARS if source.get(name, "").strip())


def enforce_isolation(environ: dict[str, str] | None = None) -> None:
    """Refuse to start where a real provider credential is reachable."""
    present = provider_keys_present(environ)
    if present:
        raise LabRefusedToStart(
            "refusing to start: this is an intentionally vulnerable application and "
            f"{', '.join(present)} is set in its environment. It follows injected "
            "instructions and renders model output as HTML; pointed at a real model "
            "that is an exfiltration path and a bill. Unset the variable, or run the "
            "lab through `docker compose --profile demo up`, where the network is "
            "internal and no credential is passed in."
        )


def bind_host(environ: dict[str, str] | None = None) -> str:
    """Loopback unless an operator deliberately says otherwise.

    `LAB_HOST` exists because the container has to bind `0.0.0.0` to be
    reachable from the worker on the compose network — a network declared
    `internal: true`, with no route off the host. Outside that, the default
    keeps the lab off every interface but the local one.
    """
    source = os.environ if environ is None else environ
    return source.get("LAB_HOST", DEFAULT_HOST).strip() or DEFAULT_HOST


def announce(service: str, environ: dict[str, str] | None = None) -> None:
    """Print the §2.4 banner. Always, and to stderr so a piped stdout keeps it."""
    enforce_isolation(environ)
    print(BANNER, file=sys.stderr)
    print(f"  service: {service}   bind: {bind_host(environ)}\n", file=sys.stderr)
