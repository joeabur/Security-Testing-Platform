"""Running a third-party scanner as a subprocess (docs/BUILD_SPEC.md §15).

Three rules from §15 and §28 are enforced here rather than left to each
adapter:

* **A missing tool degrades gracefully.** An adapter whose binary is absent
  reports that it did not run — it never crashes the assessment and never
  looks like a clean result.
* **No shell.** Commands are argument lists executed without a shell, so a
  path or a rule name containing a metacharacter is an argument, not syntax.
* **The subprocess is an outbound path.** §6.3's no-ungated-HTTP rule
  extends to tools that make their own network calls, so every adapter that
  can reach the network must be launched with an explicit offline or
  scope-derived configuration, or not launched at all. `network` on
  `ToolInvocation` is that declaration, and it is required.
"""

import asyncio
import os
import shutil
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

DEFAULT_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 32 * 1024 * 1024


class NetworkUse(StrEnum):
    """What a tool invocation is permitted to do with the network."""

    # The command is configured to make no network calls at all. This is the
    # default for every scanner that supports it.
    OFFLINE = "offline"
    # The command reaches a declared service (an advisory database) because
    # the operator opted in. The adapter names the service in its finding.
    DECLARED_SERVICE = "declared_service"


@dataclass(frozen=True)
class ToolInvocation:
    command: tuple[str, ...]
    # `None` for a tool that has no meaningful working directory — a network
    # scanner reads no files from the checkout, and inventing a cwd for it would
    # suggest it does.
    cwd: Path | None
    network: NetworkUse
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    # Extra environment for this call only; the parent environment is passed
    # through so tools find their own interpreters, minus anything a scanner
    # has no business reading.
    env: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolResult:
    ran: bool
    exit_code: int | None
    stdout: str
    stderr: str
    reason: str = ""

    @property
    def failed(self) -> bool:
        return self.ran and self.exit_code not in (0, 1)


# Variables a scanner subprocess has no reason to read. Removing them keeps a
# tool's crash report or telemetry from carrying this platform's own
# credentials off the machine.
_STRIPPED_ENV_PREFIXES = ("KERVY_", "JWT_", "DATABASE_", "REDIS_", "POSTGRES_")
_STRIPPED_ENV_NAMES = frozenset({"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN"})


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def tool_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(_STRIPPED_ENV_PREFIXES) and key not in _STRIPPED_ENV_NAMES
    }
    env.update(extra or {})
    return env


async def run_tool(invocation: ToolInvocation) -> ToolResult:
    """Run one scanner, capturing its output.

    A non-zero exit is not automatically a failure: most scanners exit 1 to
    mean "findings present", which is a successful run with results. Only an
    exit code outside {0, 1}, a timeout, or a missing binary is a failure,
    and each is reported as a reason rather than raised.
    """
    binary = invocation.command[0]
    if not tool_available(binary):
        return ToolResult(
            ran=False,
            exit_code=None,
            stdout="",
            stderr="",
            reason=f"{binary} is not installed on this worker",
        )

    try:
        process = await asyncio.create_subprocess_exec(
            *invocation.command,
            cwd=str(invocation.cwd) if invocation.cwd is not None else None,
            env=tool_environment(invocation.env),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return ToolResult(
            ran=False,
            exit_code=None,
            stdout="",
            stderr="",
            reason=f"could not start {binary}: {exc}",
        )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=invocation.timeout_seconds
        )
    except TimeoutError:
        process.kill()
        await process.wait()
        return ToolResult(
            ran=False,
            exit_code=None,
            stdout="",
            stderr="",
            reason=f"{binary} exceeded its {invocation.timeout_seconds}s timeout",
        )

    return ToolResult(
        ran=True,
        exit_code=process.returncode,
        stdout=stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"),
        stderr=stderr[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"),
    )
