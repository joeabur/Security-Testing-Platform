"""What a plugin is, and what the platform promises it (docs/BUILD_SPEC.md §16).

**No sandbox is claimed.** §16 is explicit about this and so is this module: a
third-party plugin is Python code running in the worker process. It can import
anything, open a socket, and read the filesystem — the same as any dependency
in `requirements.txt`. Pretending otherwise would be the most dangerous thing
this file could do, because an operator who believes a plugin is contained will
install one they have not read.

What the platform does provide is narrower and real:

* **Nothing loads unless it is allowed.** Discovery is opt-in per package
  (`app/plugins/allowlist.py`), and `--no-plugins` turns the mechanism off
  entirely.
* **The interface offers no ungated route to a target.** A probe plugin is
  handed a `RunContext` and a `GatedTransport`; there is no attribute on
  either that yields a raw client, so a plugin that stays inside the contract
  cannot reach a host the scope engine has not approved, and cannot exceed the
  run's budget. A plugin that leaves the contract — importing `httpx` itself —
  is untrusted code doing untrusted things, which is what the allowlist is for.
* **Bad metadata fails loudly at load**, rather than producing a probe whose
  results cannot be attributed.

The simplified interface from §16 is `SecurityTest`: an id, a name, a
category, and an async `run(target, context)` returning `ScanResult` values.
It exists because the full `Probe` protocol asks for more than an author
writing one check should have to think about.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from app.core.probes.models import Category, ScanResult
from app.core.probes.protocol import ProbeTarget
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport

# The four entry-point groups §16 names. A package publishes into the group
# that matches what it provides; anything published into a group the platform
# does not know is ignored with a warning rather than guessed at.
PROBE_GROUP = "kervy.probes"
DETECTOR_GROUP = "kervy.detectors"
ADAPTER_GROUP = "kervy.adapters"
REPORTER_GROUP = "kervy.reporters"


class PluginKind(StrEnum):
    PROBE = "probe"
    DETECTOR = "detector"
    ADAPTER = "adapter"
    REPORTER = "reporter"


GROUPS: dict[str, PluginKind] = {
    PROBE_GROUP: PluginKind.PROBE,
    DETECTOR_GROUP: PluginKind.DETECTOR,
    ADAPTER_GROUP: PluginKind.ADAPTER,
    REPORTER_GROUP: PluginKind.REPORTER,
}


class PluginError(RuntimeError):
    """A plugin could not be loaded, or was refused.

    Raised loudly rather than logged and skipped when the problem is the
    plugin's own metadata: a probe whose results cannot be attributed to a
    known id and version is worse than a probe that is absent, because it
    reaches a report looking like everything else.
    """


@dataclass(frozen=True)
class PluginContext:
    """Everything a plugin gets, and nothing else.

    A deliberately small surface. It carries the gated transport and the run
    context; it does not carry a database session, the settings object, the
    evidence store, or a credential — a plugin that needs one of those is
    asking for something this contract should not silently grant.
    """

    ctx: RunContext
    transport: GatedTransport
    safe_mode: bool = True


@runtime_checkable
class SecurityTest(Protocol):
    """The simplified §16 interface, for the common case of one check.

    `category` is a string here rather than the `Category` enum so a plugin
    author does not have to import from `app.core`; it is validated against
    the enum at load, and an unknown category fails loudly.
    """

    id: str
    name: str
    category: str

    async def run(self, target: ProbeTarget, context: PluginContext) -> list[ScanResult]: ...


@dataclass(frozen=True)
class PluginRecord:
    """One loaded plugin, with where it came from.

    `distribution` and `version` are recorded because the startup banner has
    to name them: an operator debugging an unexpected finding needs to know
    which installed package produced it, and "some plugin" is not an answer.
    """

    name: str
    kind: PluginKind
    group: str
    distribution: str
    version: str
    obj: Any
    first_party: bool = False

    def describe(self) -> str:
        origin = "built-in" if self.first_party else f"{self.distribution} {self.version}"
        return f"{self.kind.value}:{self.name} ({origin})"


def validate_security_test(obj: Any, *, source: str) -> None:
    """Check a plugin against the §16 contract before it can run.

    Every failure here is a refusal, not a warning. §16: "plugins validated
    against the `ProbeMeta` schema at load; invalid metadata fails loudly."
    """
    for attribute in ("id", "name", "category"):
        value = getattr(obj, attribute, None)
        if not isinstance(value, str) or not value.strip():
            raise PluginError(
                f"{source}: plugin is missing a non-empty string `{attribute}`; "
                "a finding that cannot be attributed to an id is worse than no finding"
            )

    runner = getattr(obj, "run", None)
    if not callable(runner):
        raise PluginError(f"{source}: plugin has no callable `run`")

    category = obj.category
    try:
        Category(str(category))
    except ValueError as exc:
        known = ", ".join(sorted(item.value for item in Category))
        raise PluginError(
            f"{source}: unknown category {category!r}. Known categories: {known}"
        ) from exc
