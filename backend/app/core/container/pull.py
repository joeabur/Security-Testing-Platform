"""Pulling an authorized container image (docs/roadmap.md, Pentest module
Phase 3).

`docker` does not route through `GatedTransport`, so the controls the
transport would have applied are applied here first, before `docker pull`
ever starts — the same pattern `app/core/appsec/checkout.py` already
established for `git clone`:

* **The registry must be explicitly allowlisted.** `image_ref` is
  operator-supplied and therefore untrusted input; without an allowlist it
  is a request-forgery primitive pointed at whatever registry the worker
  can reach.
* **The resolved address is checked against the scope engine's own blocked
  ranges** (`is_blocked_ip`), not a second implementation — a registry name
  that is allowlisted but resolves to loopback, an RFC1918 address, or the
  cloud metadata service is still refused.
* **The pulled image is removed once scanning finishes**, whether or not it
  succeeded — a pulled image sitting on the worker is exactly the kind of
  leftover artifact `discard_checkout` exists to avoid for a repository
  checkout, and the same reasoning applies here.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from app.core.appsec.checkout import HostResolver, default_host_resolver
from app.core.appsec.tooling import NetworkUse, ToolInvocation, ToolResult, run_tool
from app.core.scope.hostmatch import hostname_matches_any, is_blocked_ip, parse_ip_ranges

PULL_TIMEOUT_SECONDS = 300
REMOVE_TIMEOUT_SECONDS = 60

# Docker Hub is addressed as "docker.io" in an image reference but pulled
# from a different, specific host — the same distinction `checkout.py` has
# no need for, since a git host's name and its address are the same thing.
_DEFAULT_REGISTRY = "docker.io"
_DEFAULT_REGISTRY_RESOLVE_HOST = "registry-1.docker.io"


class ContainerPullError(RuntimeError):
    """The image reference is unusable, its registry is out of scope, or the
    pull itself failed."""


@dataclass(frozen=True)
class ImageRef:
    #: The original, trimmed reference — passed to `docker pull`/`docker rmi`
    #: verbatim rather than reconstructed, so there is only one place that
    #: could get the reconstruction wrong.
    raw: str
    #: The registry as it appears in (or is implied by) the reference, for
    #: matching against `asset_scope.allowed_registries` — "docker.io" for an
    #: unqualified name, matching what an operator would actually write.
    registry: str
    #: The host actually resolved and dialed for this registry — differs
    #: from `registry` only for Docker Hub.
    resolve_host: str
    repository: str
    tag: str | None
    digest: str | None


def parse_image_ref(raw: str) -> ImageRef:
    """Parse `nginx`, `nginx:1.25`, `nginx@sha256:...`, `ghcr.io/org/app:tag`,
    or `registry.internal:5000/app:v2` into its registry, repository, and
    reference — the registry-host extraction `app.core.appsec.supplychain
    .manifests._split_image` does not need for its own purpose (a Dockerfile
    `FROM` line's name and tag only).
    """
    candidate = raw.strip()
    if not candidate:
        raise ContainerPullError("image_ref is empty")
    if any(char.isspace() for char in candidate):
        raise ContainerPullError(f"image_ref {raw!r} contains whitespace")

    digest: str | None = None
    remainder = candidate
    if "@" in candidate:
        remainder, _, digest_part = candidate.rpartition("@")
        if not digest_part.startswith("sha256:") or len(digest_part) != len("sha256:") + 64:
            raise ContainerPullError(f"image_ref {raw!r} has a malformed digest")
        digest = digest_part
        if not remainder:
            raise ContainerPullError(f"image_ref {raw!r} has no repository name")

    # Split off a tag from the last path segment only, so a registry port
    # (`registry.internal:5000/app`) is never misread as a tag — the same
    # trick `_split_image` uses.
    tail = remainder.rsplit("/", 1)[-1]
    tag: str | None = None
    name_part = remainder
    if ":" in tail:
        name_part, tag = remainder.rsplit(":", 1)

    if not name_part:
        raise ContainerPullError(f"image_ref {raw!r} has no repository name")

    segments = name_part.split("/", 1)
    first = segments[0]
    looks_like_registry_host = "." in first or ":" in first or first == "localhost"
    if len(segments) == 2 and looks_like_registry_host:
        registry = first
        repository = segments[1]
    else:
        registry = _DEFAULT_REGISTRY
        # Docker Hub's own convention: an unqualified single-segment name
        # (`nginx`) lives under the `library/` namespace.
        repository = name_part if "/" in name_part else f"library/{name_part}"

    if not repository:
        raise ContainerPullError(f"image_ref {raw!r} has no repository path")

    resolve_host = (
        _DEFAULT_REGISTRY_RESOLVE_HOST
        if registry == _DEFAULT_REGISTRY
        else registry.split(":", 1)[0]
    )

    return ImageRef(
        raw=candidate,
        registry=registry,
        resolve_host=resolve_host,
        repository=repository,
        tag=tag,
        digest=digest,
    )


def check_registry_allowed(
    ref: ImageRef,
    allowed_registries: tuple[str, ...],
    *,
    allowed_ip_ranges: tuple[str, ...] = (),
    resolver: HostResolver | None = None,
) -> None:
    """Refuse a registry that was not explicitly authorized.

    Fail closed: an empty allowlist permits nothing — the same reading
    `checkout.py::check_host_allowed` and `resolve_container_scope` already
    give an unstated allowlist.
    """
    if not allowed_registries:
        raise ContainerPullError(
            "no registries are allowlisted for this target. Declare the registry in "
            "asset_scope.allowed_registries before pulling; an unstated registry list "
            "is not a permissive one"
        )

    # Matched against both the full registry (so an operator can allowlist
    # `registry.internal:5000` exactly, port included) and the port-stripped
    # resolve host (so a wildcard pattern like `*.internal` matches a
    # registry on a non-default port the way an operator would expect —
    # `hostname_matches`'s suffix check has no notion of a port to ignore).
    candidates = {ref.registry, ref.resolve_host}
    if not any(hostname_matches_any(candidate, allowed_registries) for candidate in candidates):
        raise ContainerPullError(
            f"registry {ref.registry!r} is not in asset_scope.allowed_registries "
            f"({', '.join(allowed_registries)})"
        )

    resolve = resolver or default_host_resolver
    try:
        addresses = [ipaddress.ip_address(value) for value in resolve(ref.resolve_host)]
    except (OSError, ValueError) as exc:
        raise ContainerPullError(
            f"could not resolve registry host {ref.resolve_host!r}: {exc}"
        ) from exc

    if not addresses:
        raise ContainerPullError(
            f"registry host {ref.resolve_host!r} did not resolve to any address"
        )

    ranges = parse_ip_ranges(allowed_ip_ranges)
    for address in addresses:
        if is_blocked_ip(address, ranges):
            raise ContainerPullError(
                f"registry host {ref.resolve_host!r} resolves to blocked address {address}; "
                "refusing to pull from a loopback, private or metadata address"
            )


async def pull_image(ref: ImageRef) -> ToolResult:
    return await run_tool(
        ToolInvocation(
            command=("docker", "pull", "--quiet", ref.raw),
            cwd=None,
            network=NetworkUse.DECLARED_SERVICE,
            timeout_seconds=PULL_TIMEOUT_SECONDS,
        )
    )


async def remove_image(ref: ImageRef) -> ToolResult:
    """Best-effort cleanup — always attempted, its result never raised, the
    same "the checkout is removed whatever happened" discipline
    `discard_checkout` follows for a git clone."""
    return await run_tool(
        ToolInvocation(
            command=("docker", "rmi", "--force", ref.raw),
            cwd=None,
            network=NetworkUse.OFFLINE,
            timeout_seconds=REMOVE_TIMEOUT_SECONDS,
        )
    )
