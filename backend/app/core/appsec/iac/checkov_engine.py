"""Checkov adapter — infrastructure-as-code analysis
(Implementation Specification §5).

IaC replaces RASP in the MVP engine set per `docs/BUILD_SPEC.md` §4.5 row 5.
Checkov runs offline against the in-scope directory with its own check ids,
which are the identifiers reported — nothing is synthesised.
"""

import json
from typing import Any

from app.core.appsec.contract import (
    EngineMeta,
    Pillar,
    code_evidence,
    finding_fingerprint,
    severity_from,
    tool_unavailable,
)
from app.core.appsec.identifiers import is_rule_id, verified_cwes
from app.core.appsec.tooling import NetworkUse, ToolInvocation, run_tool
from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity

CHECKOV_TIMEOUT_SECONDS = 420

_IAC_SUFFIXES = frozenset({".tf", ".tfvars", ".yaml", ".yml", ".json", ".hcl"})
_IAC_FILENAMES = frozenset({"Dockerfile", "docker-compose.yml", "docker-compose.yaml"})


class CheckovEngine:
    meta = EngineMeta(
        id="appsec.iac.checkov",
        version="1.0.0",
        name="Checkov (infrastructure as code)",
        pillar=Pillar.IAC,
        tool="checkov",
        description="Static analysis of Terraform, Kubernetes, Dockerfiles and CloudFormation.",
    )

    def applies_to(self, workspace: Workspace) -> bool:
        return any(
            path.suffix.lower() in _IAC_SUFFIXES or path.name in _IAC_FILENAMES
            for path in workspace.files
        )

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        result = await run_tool(
            ToolInvocation(
                command=(
                    "checkov",
                    "--directory",
                    ".",
                    "--output",
                    "json",
                    "--compact",
                    "--quiet",
                    "--skip-download",  # no network: use the bundled policies
                ),
                cwd=workspace.root,
                network=NetworkUse.OFFLINE,
                timeout_seconds=CHECKOV_TIMEOUT_SECONDS,
            )
        )
        if not result.ran:
            return [tool_unavailable(self.meta, result.reason)]
        if result.failed:
            return [
                tool_unavailable(
                    self.meta, f"checkov exited {result.exit_code}: {result.stderr[:400]}"
                )
            ]

        try:
            payload = json.loads(result.stdout or "{}")
        except ValueError as exc:
            return [tool_unavailable(self.meta, f"checkov output was not JSON: {exc}")]

        return self.parse(payload, workspace)

    def parse(self, payload: Any, workspace: Workspace) -> list[ScanResult]:
        # Checkov emits an object for one framework and a list when several
        # ran, so both shapes are handled rather than assuming one.
        reports = payload if isinstance(payload, list) else [payload]
        in_scope = set(workspace.relative_files)
        findings: list[ScanResult] = []

        for report in reports:
            if not isinstance(report, dict):
                continue
            results = report.get("results", {})
            for item in results.get("failed_checks", []) or []:
                normalized = self._normalize(item, in_scope)
                if normalized is not None:
                    findings.append(normalized)
        return findings

    def _normalize(self, item: dict[str, Any], in_scope: set[str]) -> ScanResult | None:
        check_id = str(item.get("check_id", "")).strip()
        if not is_rule_id(check_id):
            return None

        relative = str(item.get("file_path", "")).lstrip("/")
        # Checkov is pointed at the workspace root, so it can reach a file the
        # code scope excluded. Dropping those here keeps the scope boundary
        # authoritative even when a tool does not honour it natively.
        if relative not in in_scope:
            return None

        lines = item.get("file_line_range") or []
        line = lines[0] if lines else None
        snippet = "\n".join(
            str(part[1]) for part in (item.get("code_block") or []) if isinstance(part, list)
        )[:400]
        resource = str(item.get("resource", ""))

        return ScanResult(
            id=f"KERVY-IAC-{check_id}",
            title=f"{check_id}: {item.get('check_name', 'infrastructure misconfiguration')}"[:300],
            category=Category.INFRASTRUCTURE,
            severity=severity_from(str(item.get("severity") or ""), Severity.MEDIUM),
            confidence=Confidence.HIGH,
            endpoint=f"{relative}:{line}" if line else relative,
            description=(
                f"{item.get('check_name', '')}\n\nReported by checkov policy {check_id} "
                f"on resource {resource or 'unnamed'}. This describes the declared "
                "infrastructure, not the deployed state: confirm whether the resource is "
                "actually provisioned this way before scheduling work."
            ),
            evidence=(
                f"{relative}:{line}\nresource: {resource}\n{snippet}"
                if snippet
                else f"{relative}:{line}\nresource: {resource}"
            ),
            impact=(
                "A misconfigured resource definition becomes a misconfigured resource "
                "the next time this code is applied, whatever the current live state is."
            ),
            remediation=(
                f"Review {relative} against checkov's guidance for {check_id}. "
                + str(item.get("guideline") or "")
            ).strip(),
            probe_id=self.meta.id,
            probe_version=self.meta.version,
            frameworks=verified_cwes(item.get("cwe") or []),
            reproduction=(
                f"Run: checkov --directory . --check {check_id}",
                f"Observe {check_id} failing on {resource or relative}.",
            ),
            fingerprint=finding_fingerprint(
                rule_id=check_id, relative_path=relative, snippet=resource or snippet
            ),
            evidence_bundle=code_evidence(
                self.meta,
                rule_id=check_id,
                relative_path=relative,
                line=line if isinstance(line, int) else None,
                snippet=snippet,
                message=str(item.get("check_name", "")),
            ),
        )
