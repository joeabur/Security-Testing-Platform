"""Semgrep adapter — multi-language SAST via SARIF (docs/BUILD_SPEC.md §15).

Semgrep is run with `--metrics=off` and a local ruleset so the invocation
makes no network calls: §6.3's no-ungated-HTTP rule covers a subprocess
that would phone home just as it covers an `httpx` client.

SARIF is parsed rather than Semgrep's native JSON because SARIF is the
interchange format the addendum names, and the same parser will serve any
other SARIF-emitting tool added later.
"""

import json
from pathlib import Path
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

MAX_SNIPPET_CHARS = 400
SEMGREP_TIMEOUT_SECONDS = 600


def _cwes_from_tags(tags: Any) -> tuple[str, ...]:
    """CWEs that Semgrep's own rule metadata declares.

    A tag reads `CWE-89: SQL Injection`; the number before the colon is the
    rule author's claim. Nothing is inferred from the rule's description —
    §0 forbids inventing a mapping, and a plausible CWE is still invented.
    """
    if not isinstance(tags, list):
        return ()
    candidates: list[str] = []
    for tag in tags:
        text = str(tag).strip()
        if text.upper().startswith("CWE-"):
            candidates.append(text.split(":", 1)[0].strip())
    return verified_cwes(candidates)


class SemgrepEngine:
    meta = EngineMeta(
        id="appsec.sast.semgrep",
        version="1.0.0",
        name="Semgrep (static analysis)",
        pillar=Pillar.SAST,
        tool="semgrep",
        description="Multi-language static analysis driven by community rulesets.",
    )

    # The bundled local ruleset. A registry ruleset such as `p/default`
    # downloads rules over the network, which §6.3 governs like any other
    # outbound path, so it is an explicit operator choice rather than the
    # default.
    LOCAL_RULES = Path(__file__).parent / "rules"

    def __init__(self, config: str | None = None) -> None:
        self._config = config or str(self.LOCAL_RULES)

    def applies_to(self, workspace: Workspace) -> bool:
        return bool(workspace.files)

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        result = await run_tool(
            ToolInvocation(
                command=(
                    "semgrep",
                    "--sarif",
                    "--quiet",
                    "--metrics=off",
                    "--disable-version-check",
                    "--config",
                    self._config,
                    *sorted({str(path) for path in workspace.files}),
                ),
                cwd=workspace.root,
                network=NetworkUse.OFFLINE,
                timeout_seconds=SEMGREP_TIMEOUT_SECONDS,
                env={"SEMGREP_SEND_METRICS": "off"},
            )
        )
        if not result.ran:
            return [tool_unavailable(self.meta, result.reason)]
        if result.failed:
            return [
                tool_unavailable(
                    self.meta, f"semgrep exited {result.exit_code}: {result.stderr[:400]}"
                )
            ]

        try:
            sarif = json.loads(result.stdout or "{}")
        except ValueError as exc:
            return [tool_unavailable(self.meta, f"semgrep output was not SARIF JSON: {exc}")]

        return self.parse_sarif(sarif, workspace)

    def parse_sarif(self, sarif: dict[str, Any], workspace: Workspace) -> list[ScanResult]:
        findings: list[ScanResult] = []

        for run in sarif.get("runs", []):
            rules = {
                str(rule.get("id")): rule
                for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
                if isinstance(rule, dict)
            }
            for item in run.get("results", []):
                normalized = self._normalize(item, rules, workspace)
                if normalized is not None:
                    findings.append(normalized)
        return findings

    def _normalize(
        self, item: dict[str, Any], rules: dict[str, Any], workspace: Workspace
    ) -> ScanResult | None:
        rule_id = str(item.get("ruleId", "")).strip()
        if not is_rule_id(rule_id):
            return None

        locations = item.get("locations") or []
        if not locations:
            return None
        physical = locations[0].get("physicalLocation", {})
        relative = relative_to_workspace(
            str(physical.get("artifactLocation", {}).get("uri", "")), workspace
        )
        # Outside the workspace, or unreadable: not this scan's to report.
        if relative is None:
            return None
        region = physical.get("region", {})
        line = region.get("startLine")
        snippet = str(region.get("snippet", {}).get("text", ""))[:MAX_SNIPPET_CHARS]

        rule = rules.get(rule_id, {})
        properties = rule.get("properties", {}) if isinstance(rule, dict) else {}
        message = str(item.get("message", {}).get("text", "")).strip()

        return ScanResult(
            id=f"KERVY-SAST-{rule_id.split('.')[-1][:40]}",
            title=f"{rule_id}: {message}"[:300] or rule_id,
            category=Category.INFRASTRUCTURE,
            severity=severity_from(
                str(item.get("level") or properties.get("security-severity") or ""),
                Severity.MEDIUM,
            ),
            confidence=Confidence.MEDIUM,
            endpoint=f"{relative}:{line}" if line else relative,
            description=(
                f"{message}\n\nReported by semgrep rule {rule_id}. This is a static "
                "observation on the committed source: reproducible on this commit, and "
                "not in itself evidence that the path is reachable at runtime."
            ),
            evidence=f"{relative}:{line}\n{snippet}" if snippet else f"{relative}:{line}",
            impact=(
                "Static analysis identifies the defect, not its exploitability. Confirm "
                "reachability with attacker-influenced input before scheduling work."
            ),
            remediation=(
                f"Review {relative}:{line} against the guidance for {rule_id}. Record a "
                "deliberate exception in the tool's configuration rather than deleting "
                "the finding."
            ),
            probe_id=self.meta.id,
            probe_version=self.meta.version,
            frameworks=_cwes_from_tags(properties.get("tags")),
            reproduction=(
                f"Run: semgrep --config {self._config} {relative}",
                f"Observe rule {rule_id} reported at line {line}.",
            ),
            fingerprint=finding_fingerprint(
                rule_id=rule_id, relative_path=relative, snippet=snippet
            ),
            evidence_bundle=code_evidence(
                self.meta,
                rule_id=rule_id,
                relative_path=relative,
                line=line if isinstance(line, int) else None,
                snippet=snippet,
                message=message,
            ),
        )
