"""Fetching an authorized repository (docs/BUILD_SPEC.md §6.3; Addendum §3).

Cloning is an outbound network operation performed by a subprocess, so it
gets the same treatment as any other request this platform makes. `git` does
not route through `GatedTransport`, so the controls the transport would have
applied are applied here instead, before `git` is ever started:

* **The host must be explicitly allowlisted.** A repository reference is
  operator-supplied and therefore untrusted input. Without an allowlist,
  `repo_ref` is a request-forgery primitive pointed at whatever the worker
  can reach.
* **The resolved address is checked against the scope engine's own blocked
  ranges** — link-local, loopback, RFC1918, cloud metadata — using
  `is_blocked_ip`, not a second implementation. `https://github.com.evil/`
  and `https://internal-git/` both fail here.
* **Only https and file are accepted.** `ext::` turns a clone into arbitrary
  command execution, and `git://` is unauthenticated plaintext.
* **Submodules are never fetched.** A `.gitmodules` in an untrusted
  repository points wherever its author chose, which would reintroduce
  every check above from inside the clone.
* **Hooks are disabled and the terminal prompt is off**, so a clone cannot
  execute repository-controlled code or hang waiting for credentials.

The checkout is removed when the run finishes. A working copy of a client's
repository is exactly the thing that should not be left on a worker: it is
the material a secret scan just found credentials in.
"""

import ipaddress
import shutil
import socket
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from app.core.appsec.tooling import NetworkUse, ToolInvocation, run_tool
from app.core.scope.hostmatch import is_blocked_ip, parse_ip_ranges

CLONE_TIMEOUT_SECONDS = 300
ALLOWED_SCHEMES = frozenset({"https", "file"})

# `git+https://host/path#ref` is the form §3 of the addendum uses.
_GIT_PREFIX = "git+"

# Injected so tests, and a future scope-aware resolver, can substitute for
# the system one without this module reaching for DNS itself.
HostResolver = Callable[[str], list[str]]


class CheckoutError(RuntimeError):
    """The repository reference is unusable, out of scope, or unreachable."""


@dataclass(frozen=True)
class RepositoryRef:
    scheme: str
    host: str
    url: str
    revision: str | None = None

    @property
    def is_local(self) -> bool:
        return self.scheme == "file"


def parse_repo_ref(raw: str) -> RepositoryRef:
    """Parse `git+https://host/org/repo.git#branch` into its parts."""
    candidate = raw.strip()
    if candidate.startswith(_GIT_PREFIX):
        candidate = candidate[len(_GIT_PREFIX) :]

    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise CheckoutError(
            f"repository scheme {scheme or '(none)'!r} is not permitted; use https "
            "for a remote repository or file for a local path. ext:: and git:// are "
            "refused because one executes commands and the other is unauthenticated."
        )

    # Credentials embedded in a URL end up in process listings and logs.
    if parts.username or parts.password:
        raise CheckoutError(
            "repository URL contains inline credentials; supply them through the "
            "worker's git configuration instead, where they are not logged"
        )

    url = candidate.split("#", 1)[0]
    revision = parts.fragment or None
    return RepositoryRef(scheme=scheme, host=parts.hostname or "", url=url, revision=revision)


def default_host_resolver(host: str) -> list[str]:
    """Every address a hostname resolves to, as strings."""
    return sorted({str(info[4][0]) for info in socket.getaddrinfo(host, None)})


def check_host_allowed(
    ref: RepositoryRef,
    allowed_hosts: tuple[str, ...],
    *,
    allowed_ip_ranges: tuple[str, ...] = (),
    resolver: HostResolver | None = None,
) -> None:
    """Refuse a repository host that was not explicitly authorized.

    Fail closed: an empty allowlist permits nothing. The alternative —
    treating "unstated" as "any host" — makes an operator-supplied
    `repo_ref` into a way to reach anything the worker can reach.
    """
    if ref.is_local:
        return

    if not allowed_hosts:
        raise CheckoutError(
            "no repository hosts are allowlisted for this target. Declare the host "
            "in code_scope.allowed_repo_hosts before cloning; an unstated host list "
            "is not a permissive one."
        )

    host = ref.host.lower().rstrip(".")
    if host not in {item.lower().rstrip(".") for item in allowed_hosts}:
        raise CheckoutError(
            f"repository host {host!r} is not in code_scope.allowed_repo_hosts "
            f"({', '.join(allowed_hosts)})"
        )

    # Resolve and apply the scope engine's own blocked ranges, so a host that
    # is allowlisted by name but points at the metadata service or an
    # internal address is still refused.
    resolve = resolver or default_host_resolver
    try:
        addresses = [ipaddress.ip_address(value) for value in resolve(host)]
    except (OSError, ValueError) as exc:
        raise CheckoutError(f"could not resolve repository host {host!r}: {exc}") from exc

    if not addresses:
        raise CheckoutError(f"repository host {host!r} did not resolve to any address")

    ranges = parse_ip_ranges(allowed_ip_ranges)
    for address in addresses:
        if is_blocked_ip(address, ranges):
            raise CheckoutError(
                f"repository host {host!r} resolves to blocked address {address}; "
                "refusing to clone from a loopback, private or metadata address"
            )


async def clone_repository(ref: RepositoryRef, destination: Path, *, depth: int = 1) -> Path:
    """Clone into `destination`, with repository-controlled code disabled."""
    command = [
        "git",
        # A repository cannot run its own hooks during or after the clone.
        "-c",
        "core.hooksPath=/dev/null",
        # `ext::` makes a clone arbitrary command execution.
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "protocol.file.allow=user",
        "clone",
        "--quiet",
        "--no-tags",
        # Submodules point wherever the repository's author chose, which
        # would bypass every check applied to the top-level URL.
        "--no-recurse-submodules",
        f"--depth={depth}",
    ]
    if ref.revision:
        command += ["--branch", ref.revision]
    command += [ref.url, str(destination)]

    result = await run_tool(
        ToolInvocation(
            command=tuple(command),
            cwd=destination.parent,
            network=(NetworkUse.OFFLINE if ref.is_local else NetworkUse.DECLARED_SERVICE),
            timeout_seconds=CLONE_TIMEOUT_SECONDS,
            # Fail rather than block forever waiting for a password.
            env={"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "GCM_INTERACTIVE": "never"},
        )
    )
    if not result.ran:
        raise CheckoutError(result.reason)
    if result.exit_code != 0:
        raise CheckoutError(f"git clone failed: {result.stderr.strip()[:400]}")
    return destination


def make_checkout_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="kervy-checkout-"))


def discard_checkout(path: Path) -> None:
    """Remove a checkout. A working copy of a client's repository is exactly
    what should not be left behind on a worker."""
    shutil.rmtree(path, ignore_errors=True)
