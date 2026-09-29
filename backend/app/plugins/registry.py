"""Loading plugins, and saying out loud what loaded (docs/BUILD_SPEC.md §16).

Two properties this module is built to keep:

**A refusal is never silent.** A package that is not allowlisted, a plugin
whose metadata is invalid, a module that raises on import — each produces a
recorded reason. An operator who added a plugin and sees no findings from it
must be able to learn why without reading source.

**One bad plugin does not lose the run.** An import that raises is recorded as
a refusal and the rest still load, on the same principle the orchestrator
applies to probes: a run with a visible hole is more useful than no run.
"""

from dataclasses import dataclass, field
from importlib.metadata import EntryPoint, entry_points

import structlog

from app.plugins.allowlist import PluginPolicy
from app.plugins.contract import (
    GROUPS,
    PluginError,
    PluginKind,
    PluginRecord,
    validate_security_test,
)

logger = structlog.get_logger()


@dataclass
class DiscoveryResult:
    loaded: list[PluginRecord] = field(default_factory=list)
    # A plugin that was found and turned away: not allowlisted, bad metadata,
    # failed to import. Per-plugin, and worth putting in a run's event log.
    refused: list[str] = field(default_factory=list)
    # Why discovery itself did nothing — no configuration, or explicitly off.
    # Kept apart from `refused` so a deployment that simply runs no plugins does
    # not file an event on every single run saying so.
    notes: list[str] = field(default_factory=list)

    def of_kind(self, kind: PluginKind) -> list[PluginRecord]:
        return [record for record in self.loaded if record.kind is kind]

    def banner(self) -> str:
        """The §16 startup banner.

        Printed whether or not anything loaded, and it says so when nothing
        did — "no third-party plugins" is information an operator wants, and a
        banner that appears only sometimes is one nobody learns to read.
        """
        lines = ["Kervy plugins:"]
        third_party = [record for record in self.loaded if not record.first_party]
        if third_party:
            lines.append(
                f"  {len(third_party)} third-party plugin(s) loaded — these run "
                "in this process and are not sandboxed:"
            )
            lines += [
                f"    - {record.describe()}"
                for record in sorted(third_party, key=lambda record: record.name)
            ]
        else:
            lines.append("  no third-party plugins loaded")
        if self.refused:
            lines.append(f"  {len(self.refused)} refused:")
            lines += [f"    - {reason}" for reason in self.refused]
        lines += [f"  {note}" for note in self.notes]
        return "\n".join(lines)


def discover(
    policy: PluginPolicy, *, groups: dict[str, PluginKind] | None = None
) -> DiscoveryResult:
    """Load every allowed plugin from the §16 entry-point groups.

    `groups` is injectable so the tests can exercise discovery without
    installing packages into the interpreter running them.
    """
    result = DiscoveryResult()
    if not policy.enabled:
        # Not an error and not a silence: the banner says plugins are off, and
        # why, without turning that into a per-run event.
        result.notes.extend(policy.warnings)
        return result

    for group, kind in (groups or GROUPS).items():
        for entry in _entry_points(group):
            record = _load_one(entry, group, kind, policy, result)
            if record is not None:
                result.loaded.append(record)
    return result


def _entry_points(group: str) -> list[EntryPoint]:
    try:
        return list(entry_points(group=group))
    except Exception as exc:  # noqa: BLE001 - a broken environment is not a crash
        logger.warning("plugin.entry_points_failed", group=group, error=str(exc))
        return []


def _load_one(
    entry: EntryPoint,
    group: str,
    kind: PluginKind,
    policy: PluginPolicy,
    result: DiscoveryResult,
) -> PluginRecord | None:
    distribution = _distribution_of(entry)
    source = f"{group}:{entry.name}"

    try:
        policy.check(distribution, source=source)
    except PluginError as exc:
        result.refused.append(str(exc))
        logger.info("plugin.refused", source=source, reason=str(exc))
        return None

    try:
        obj = entry.load()
    except Exception as exc:  # noqa: BLE001 - one bad plugin must not lose the rest
        reason = f"{source}: failed to import ({type(exc).__name__}: {exc})"
        result.refused.append(reason)
        logger.warning("plugin.import_failed", source=source, error=str(exc))
        return None

    # A class is the common shape; instantiate it so the rest of the platform
    # only ever deals with instances.
    if isinstance(obj, type):
        try:
            obj = obj()
        except Exception as exc:  # noqa: BLE001
            reason = f"{source}: could not be instantiated ({type(exc).__name__}: {exc})"
            result.refused.append(reason)
            return None

    if kind is PluginKind.PROBE:
        try:
            validate_security_test(obj, source=source)
        except PluginError as exc:
            # Loud: an unattributable finding reaching a report looks like
            # every other finding, which is worse than a missing probe.
            result.refused.append(str(exc))
            logger.warning("plugin.invalid", source=source, error=str(exc))
            return None

    return PluginRecord(
        name=str(getattr(obj, "id", entry.name)),
        kind=kind,
        group=group,
        distribution=distribution,
        version=_version_of(entry, distribution),
        obj=obj,
    )


def _distribution_of(entry: EntryPoint) -> str:
    dist = getattr(entry, "dist", None)
    name = getattr(dist, "name", None) if dist is not None else None
    # Unknown provenance is treated as its own name so the allowlist check
    # refuses it: a plugin the platform cannot attribute cannot be allowed.
    return str(name) if name else "<unknown-distribution>"


def _version_of(entry: EntryPoint, distribution: str) -> str:
    dist = getattr(entry, "dist", None)
    version = getattr(dist, "version", None) if dist is not None else None
    return str(version) if version else "unknown"
