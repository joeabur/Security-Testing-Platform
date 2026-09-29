"""Bandit adapter — Python SAST (docs/BUILD_SPEC.md §15; Addendum §4.1).

Bandit is invoked on the resolved in-scope file list rather than on a
directory, so the workspace's allow/exclude rules decide what is read and
the tool cannot wander outside them. It makes no network calls.
"""

import json
from typing import Any

from app.core.appsec.contract import (
    EngineMeta,
    Pillar,
    code_evidence,
    finding_fingerprint,
    relative_to_workspace,
    severity_from,
    tool_unavailable,
)
from app.core.appsec.identifiers import is_rule_id, verified_cwes
from app.core.appsec.tooling import NetworkUse, ToolInvocation, run_tool
from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity

MAX_FILES = 2000
MAX_SNIPPET_CHARS = 400

# Bandit reports its own confidence; a low-confidence hit is reported at
# reduced confidence rather than suppressed, so a reader can decide.
_CONFIDENCE = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
}

# Rules that flag the *presence* of an API rather than a *misuse* of it.
# B404 fires on `import subprocess`; B603 and B607 fire on `subprocess.run`
# with a list argument and `shell=False`, which is the correct way to call a
# subprocess. Reporting these as findings would mean a correctly-written
# program produces findings, and a scanner whose clean state is unreachable
# teaches its users to ignore it.
#
# They are **downgraded to informational, not suppressed** — §14's coverage
# honesty and §28's "no silent suppression" both apply. They stay in the
# result set, visible and attributed, and simply do not count as findings.
# The addendum anticipates exactly this case: a rule known to be
# heuristic or high-noise is reported with its confidence capped and the
# reason stated.
_ADVISORY_RULES = frozenset(
    {
        "B322",  # input() — Python 2 only, always a false positive on 3.x
        "B404",  # import subprocess
        "B603",  # subprocess call without shell=True — i.e. the safe form
        "B607",  # start process with a partial executable path
    }
)


class BanditEngine:
    meta = EngineMeta(
        id="appsec.sast.bandit",
        version="1.0.0",
        name="Bandit (Python static analysis)",
        pillar=Pillar.SAST,
        tool="bandit",
        description="Python-specific static analysis for common security defects.",
    )

    def applies_to(self, workspace: Workspace) -> bool:
        return any(path.suffix == ".py" for path in workspace.files)

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        targets = [path for path in workspace.files if path.suffix == ".py"][:MAX_FILES]
        if not targets:
            return []

        result = await run_tool(
            ToolInvocation(
                command=("bandit", "-f", "json", "-q", *(str(path) for path in targets)),
                cwd=workspace.root,
                network=NetworkUse.OFFLINE,
            )
        )
        if not result.ran:
            return [tool_unavailable(self.meta, result.reason)]
        if result.failed:
            return [
                tool_unavailable(
                    self.meta, f"bandit exited {result.exit_code}: {result.stderr[:400]}"
                )
            ]

        try:
            payload = json.loads(result.stdout or "{}")
        except ValueError as exc:
            return [tool_unavailable(self.meta, f"bandit output was not JSON: {exc}")]

        findings: list[ScanResult] = []
        for item in payload.get("results", []):
            scan_result = self._normalize(item, workspace)
            if scan_result is not None:
                findings.append(scan_result)
        return findings

    def _normalize(self, item: dict[str, Any], workspace: Workspace) -> ScanResult | None:
        rule_id = str(item.get("test_id", "")).strip()
        # A finding with no rule id cannot be fingerprinted stably or traced
        # back to an upstream rule, so it is dropped rather than given one.
        if not is_rule_id(rule_id):
            return None

        relative = relative_to_workspace(str(item.get("filename", "")), workspace)
        if relative is None:
            return None

        advisory = rule_id in _ADVISORY_RULES
        snippet = str(item.get("code", ""))[:MAX_SNIPPET_CHARS]
        line = item.get("line_number")
        cwe_raw = item.get("issue_cwe") or {}
        cwes = verified_cwes([cwe_raw.get("id")] if isinstance(cwe_raw, dict) else [])

        return ScanResult(
            id=f"KERVY-SAST-{rule_id}",
            title=f"{rule_id}: {item.get('issue_text', 'static analysis finding')}"[:300],
            category=Category.INFRASTRUCTURE,
            severity=(
                Severity.INFORMATIONAL
                if advisory
                else severity_from(str(item.get("issue_severity", "")), Severity.MEDIUM)
            ),
            confidence=(
                Confidence.DESIGN_REVIEW
                if advisory
                else _CONFIDENCE.get(
                    str(item.get("issue_confidence", "")).upper(), Confidence.MEDIUM
                )
            ),
            endpoint=f"{relative}:{line}" if line else relative,
            description=(
                f"{item.get('issue_text', '')}\n\n"
                f"Reported by bandit rule {rule_id} ({item.get('test_name', 'unnamed')}). "
                "This is a static observation on the committed source: it is reproducible "
                "on this commit and does not establish that the code path is reachable at "
                "runtime."
                + (
                    f"\n\nRecorded as informational rather than as a finding: {rule_id} "
                    "flags the presence of an API rather than a misuse of it, and fires "
                    "on correctly-written code. It is kept here rather than suppressed so "
                    "the coverage is visible."
                    if advisory
                    else ""
                )
            ),
            evidence=(f"{relative}:{line}\n{snippet}" if snippet else f"{relative}:{line}"),
            impact=(
                "Static analysis identifies the defect, not its exploitability. Confirm "
                "whether the affected path is reachable with attacker-influenced input "
                "before scheduling the work."
            ),
            remediation=(
                f"Review the code at {relative}:{line} against bandit's guidance for "
                f"{rule_id}. Suppress it in the tool's own configuration if it is a "
                "deliberate, reviewed exception — not by deleting the finding."
            ),
            probe_id=self.meta.id,
            probe_version=self.meta.version,
            frameworks=tuple(cwes),
            reproduction=(
                f"Run: bandit -f json {relative}",
                f"Observe rule {rule_id} reported at line {line}.",
            ),
            # Fingerprint on rule + path + code span, never the line number.
            fingerprint=finding_fingerprint(
                rule_id=rule_id, relative_path=relative, snippet=snippet
            ),
            evidence_bundle=code_evidence(
                self.meta,
                rule_id=rule_id,
                relative_path=relative,
                line=int(line) if isinstance(line, int) else None,
                snippet=snippet,
                message=str(item.get("issue_text", "")),
            ),
        )
