"""What a VM assessment is, and what it needs to run.

Mirrors `app/core/container/contract.py`'s shape: the engine's input is a
frozen dataclass resolved once from `RulesOfEngagementRecord.asset_scope`
(`resolve_vm_scope`), never re-read from the RoE mid-run.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class VmTarget:
    """The input to the VM engine.

    `allowed_ports` has no default the engine treats as "everything" —
    `resolve_vm_scope` itself refuses an empty list, the same "an unstated
    port allowlist is not a permissive one" rule `resolve_container_scope`
    already enforces for `allowed_registries`. Unlike `ContainerScope
    .allow_live_pull`, there is no separate opt-in flag: declaring a port in
    `allowed_ports` already is the explicit authorization to probe it — the
    same reading `DomainTarget.root_domain`'s mere presence gives the
    domain engine's baseline discovery and TLS/header checks.
    """

    host: str
    allowed_ports: tuple[int, ...] = ()


@dataclass(frozen=True)
class OpenPort:
    """One open port `nmap` found, with whatever service/version detection
    (`-sV`) recognized. `service`/`product`/`version` are empty strings, not
    `None`, when nmap could not identify them — the same "unknown, not
    absent" reading `region: str | None` avoids needing on `BucketExposure`
    only because a bucket's region is always resolvable; a port's service
    banner often is not.
    """

    port: int
    protocol: str
    service: str
    product: str
    version: str


class VmScanError(RuntimeError):
    """The host is unusable, resolves to a blocked address, or the `nmap`
    invocation itself failed."""


@dataclass(frozen=True)
class ToolInvocationRecord:
    """One subprocess call this engine made, in the shape
    `app.core.vm.service.record_tool_invocations` persists into
    `RunToolInvocation` — mirrors `app.core.container.contract
    .ToolInvocationRecord` exactly; duplicated rather than imported across
    engine packages, the same "mirror, don't share" convention every other
    per-phase `contract.py` in this module follows.
    """

    tool_name: str
    tool_version: str | None
    network_use: str
    command_summary: str
    started_at: datetime
    finished_at: datetime | None
    exit_status: int | None
