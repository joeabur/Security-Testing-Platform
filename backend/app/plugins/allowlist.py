"""Which plugins are allowed to load (docs/BUILD_SPEC.md §16).

The allowlist is the actual security control here, which is why it is a
separate module with its own tests rather than a flag inside the loader. §16
asks for "signed/allowlist mode (`plugins.allowlist` of package name + hash)"
and `--no-plugins`, and the design follows from one decision:

**Discovery is off unless an operator turns it on.** A platform that loaded
whatever was installed would let `pip install` decide what runs inside the
scope engine's process. So the default policy loads nothing third-party, and
every package has to be named.

The optional hash pins a specific distribution. It is checked against the
installed distribution's recorded contents, so an operator can say "this
package, this build" and have a later silent replacement refused. A package
listed without a hash is trusted by name, which is weaker and documented as
such — an operator who wants the stronger promise supplies the hash.
"""

import hashlib
import re
from dataclasses import dataclass, field
from importlib.metadata import Distribution, PackageNotFoundError
from pathlib import Path
from typing import Any

import yaml

from app.plugins.contract import PluginError


@dataclass(frozen=True)
class AllowedPackage:
    name: str
    # Optional on purpose: name-only is a real and common choice, and
    # pretending otherwise would push operators into fabricating hashes.
    sha256: str | None = None

    def normalized(self) -> str:
        return _normalize(self.name)


@dataclass(frozen=True)
class PluginPolicy:
    """Whether to discover plugins at all, and which packages may load."""

    enabled: bool = False
    allowlist: tuple[AllowedPackage, ...] = ()
    # When true, a package on the allowlist with a hash that does not match is
    # refused. Always true in practice; it exists so the refusal path is
    # testable without fabricating a distribution.
    verify_hashes: bool = True
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def disabled(cls) -> "PluginPolicy":
        return cls(enabled=False)

    def entry_for(self, distribution: str) -> AllowedPackage | None:
        target = _normalize(distribution)
        for item in self.allowlist:
            if item.normalized() == target:
                return item
        return None

    def check(self, distribution: str, *, source: str) -> None:
        """Raise unless this distribution may load."""
        if not self.enabled:
            raise PluginError(
                f"{source}: plugin discovery is disabled; enable it and add "
                f"{distribution!r} to plugins.allowlist to load it"
            )

        entry = self.entry_for(distribution)
        if entry is None:
            raise PluginError(
                f"{source}: {distribution!r} is not in plugins.allowlist. "
                "Third-party plugins are untrusted code and run in the worker "
                "process; nothing loads until an operator names it."
            )

        if entry.sha256 and self.verify_hashes:
            actual = distribution_hash(distribution)
            if actual is None:
                raise PluginError(
                    f"{source}: {distribution!r} is pinned to a hash but its "
                    "installed contents could not be read to check it"
                )
            if actual != entry.sha256.lower():
                raise PluginError(
                    f"{source}: {distribution!r} does not match its pinned hash "
                    f"(allowlist {entry.sha256[:16]}…, installed {actual[:16]}…). "
                    "The package was replaced since it was pinned."
                )


def distribution_hash(distribution: str) -> str | None:
    """A digest over an installed distribution's recorded file hashes.

    Built from the `RECORD` metadata rather than by re-reading every file: the
    installer already hashed each file, and re-hashing a large package on every
    worker start would cost more than it proves. The digest therefore pins
    "the build that was installed", which is the claim an operator is actually
    making when they paste a hash into the allowlist.
    """
    try:
        dist = Distribution.from_name(distribution)
    except PackageNotFoundError:
        return None

    record = dist.read_text("RECORD")
    if not record:
        return None

    # Sorted, so the digest does not depend on the order the installer wrote.
    lines = sorted(line.strip() for line in record.splitlines() if line.strip())
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def load_policy(raw: str) -> PluginPolicy:
    """Parse the `plugins:` section of an operator's configuration.

    Strict, for the same reason the security gate's parser is: a typo in a
    security control must not read as a permissive default. An unknown key is
    an error, and a malformed allowlist entry is an error.
    """
    try:
        document = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise PluginError(f"could not parse plugin configuration: {exc}") from exc
    if not isinstance(document, dict):
        raise PluginError("plugin configuration must be a mapping")

    section = document.get("plugins", document)
    if not isinstance(section, dict):
        raise PluginError("`plugins` must be a mapping")

    unknown = sorted(set(section) - {"enabled", "allowlist"})
    if unknown:
        raise PluginError(
            f"unknown plugin setting(s): {', '.join(unknown)}. Known: allowlist, enabled"
        )

    return PluginPolicy(
        enabled=_enabled(section.get("enabled")),
        allowlist=_allowlist(section.get("allowlist")),
    )


def _enabled(value: Any) -> bool:
    if value is None:
        # Absent means off. Discovery is opt-in: `pip install` must not be
        # what decides which code runs inside the scope engine's process.
        return False
    if not isinstance(value, bool):
        raise PluginError("plugins.enabled must be true or false")
    return value


def _allowlist(value: Any) -> tuple[AllowedPackage, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise PluginError("plugins.allowlist must be a list")

    out: list[AllowedPackage] = []
    for item in value:
        if isinstance(item, str):
            out.append(AllowedPackage(name=item))
            continue
        if not isinstance(item, dict):
            raise PluginError(
                "each allowlist entry must be a package name or a mapping with "
                "`name` and an optional `sha256`"
            )
        unknown = sorted(set(item) - {"name", "sha256"})
        if unknown:
            raise PluginError(f"unknown allowlist key(s): {', '.join(unknown)}")
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise PluginError("an allowlist entry needs a non-empty `name`")
        digest = item.get("sha256")
        if digest is not None and (not isinstance(digest, str) or len(digest.strip()) != 64):
            raise PluginError(f"the sha256 for {name!r} must be a 64-character hex digest")
        out.append(AllowedPackage(name=name, sha256=digest.strip().lower() if digest else None))
    return tuple(out)


# PEP 503: a run of `-`, `_` or `.` collapses to a single `-`. Collapsing the
# run matters — character-by-character substitution would make `kervy__plugin`
# normalize to `kervy--plugin` and not match an allowlist entry of
# `kervy-plugin`. That direction fails closed, but it also breaks legitimate
# entries, and getting it right costs one regex.
_NORMALIZE = re.compile(r"[-_.]+")


def _normalize(name: str) -> str:
    """PEP 503 normalization, so `Kervy_Plugin` and `kervy-plugin` are the same
    package and an allowlist cannot be sidestepped by punctuation."""
    return _NORMALIZE.sub("-", name.strip().lower())


def policy_from_settings() -> PluginPolicy:
    """The deployment's plugin policy.

    Three states, in precedence order:

    1. `KERVY_NO_PLUGINS=1` — off, whatever else is configured. This is §16's
       `--no-plugins`, and it wins deliberately: when something has gone wrong
       there should be exactly one thing to set.
    2. `PLUGINS_CONFIG` pointing at a readable file — that file's policy.
    3. Neither — off, with a note saying why, so the banner can explain the
       silence rather than leaving an operator guessing.
    """
    from app.core.config import get_settings

    settings = get_settings()
    if settings.no_plugins:
        return PluginPolicy(
            enabled=False,
            warnings=("plugin discovery is off: KERVY_NO_PLUGINS is set",),
        )

    if not settings.plugins_config:
        return PluginPolicy(
            enabled=False,
            warnings=(
                "plugin discovery is off: no PLUGINS_CONFIG is set, so no "
                "third-party package is allowed to load",
            ),
        )

    path = Path(settings.plugins_config)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        # Fail closed and say so. A misconfigured path must not become a
        # permissive default, and it must not stop the worker either.
        return PluginPolicy(
            enabled=False,
            warnings=(f"plugin discovery is off: could not read {path} ({exc})",),
        )

    try:
        return load_policy(raw)
    except PluginError as exc:
        return PluginPolicy(
            enabled=False,
            warnings=(f"plugin discovery is off: {path} is not valid ({exc})",),
        )
