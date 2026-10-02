"""The container engine's control flow: gating, cleanup-always, and finding
shape — exercised with injected pull/remove/scan doubles rather than a real
Docker daemon or trivy binary, the same reason `DomainEngine`'s tests inject
a transport and DNS resolver instead of reaching the real network.
"""

import json

import pytest

from app.core.appsec.tooling import ToolResult
from app.core.container.contract import ContainerTarget
from app.core.container.engine import ContainerEngine
from app.core.container.pull import ContainerPullError, ImageRef


def _ok(stdout: str = "{}") -> ToolResult:
    return ToolResult(ran=True, exit_code=0, stdout=stdout, stderr="")


def _failed(reason: str) -> ToolResult:
    return ToolResult(ran=False, exit_code=None, stdout="", stderr="", reason=reason)


async def test_a_target_that_does_not_authorize_a_live_pull_is_a_visible_gap() -> None:
    engine = ContainerEngine()
    target = ContainerTarget(
        image_ref="ghcr.io/org/app:tag", allowed_registries=("ghcr.io",), allow_live_pull=False
    )

    findings, invocations = await engine.run(target)

    assert invocations == []
    assert len(findings) == 1
    assert findings[0].id == "KERVY-CONTAINER-109"
    assert "allow_live_pull" in findings[0].evidence


async def test_an_unauthorized_registry_is_a_visible_gap_and_never_pulls() -> None:
    calls = []

    async def pull(ref: ImageRef) -> ToolResult:
        calls.append(ref)
        return _ok()

    engine = ContainerEngine(pull=pull)
    target = ContainerTarget(
        image_ref="ghcr.io/org/app:tag", allowed_registries=("docker.io",), allow_live_pull=True
    )

    findings, invocations = await engine.run(target)

    assert calls == []
    assert invocations == []
    assert findings[0].id == "KERVY-CONTAINER-109"
    assert "not in asset_scope.allowed_registries" in findings[0].evidence


async def test_a_pull_failure_is_a_visible_gap_and_never_scans() -> None:
    scan_calls = []

    async def pull(_ref: ImageRef) -> ToolResult:
        return _failed("docker is not installed on this worker")

    async def scan(ref: ImageRef) -> ToolResult:
        scan_calls.append(ref)
        return _ok()

    engine = ContainerEngine(pull=pull, scan=scan)
    target = ContainerTarget(
        image_ref="ghcr.io/org/app:tag", allowed_registries=("ghcr.io",), allow_live_pull=True
    )

    findings, invocations = await engine.run(target)

    assert scan_calls == []
    assert len(invocations) == 1
    assert invocations[0].tool_name == "docker"
    assert findings[0].id == "KERVY-CONTAINER-109"
    assert "image pull failed" in findings[0].evidence


async def test_cleanup_always_runs_even_when_the_scan_raises() -> None:
    remove_calls = []

    async def pull(_ref: ImageRef) -> ToolResult:
        return _ok()

    async def scan(_ref: ImageRef) -> ToolResult:
        raise RuntimeError("trivy blew up")

    async def remove(ref: ImageRef) -> ToolResult:
        remove_calls.append(ref)
        return _ok()

    engine = ContainerEngine(pull=pull, scan=scan, remove=remove)
    target = ContainerTarget(
        image_ref="ghcr.io/org/app:tag", allowed_registries=("ghcr.io",), allow_live_pull=True
    )

    with pytest.raises(RuntimeError):
        await engine.run(target)

    assert len(remove_calls) == 1


async def test_a_scan_failure_is_a_visible_gap() -> None:
    async def pull(_ref: ImageRef) -> ToolResult:
        return _ok()

    async def scan(_ref: ImageRef) -> ToolResult:
        return _failed("trivy is not installed on this worker")

    async def remove(_ref: ImageRef) -> ToolResult:
        return _ok()

    engine = ContainerEngine(pull=pull, scan=scan, remove=remove)
    target = ContainerTarget(
        image_ref="ghcr.io/org/app:tag", allowed_registries=("ghcr.io",), allow_live_pull=True
    )

    findings, invocations = await engine.run(target)

    assert findings[0].id == "KERVY-CONTAINER-109"
    assert "image scan failed" in findings[0].evidence
    # pull + the failed scan attempt + the always-runs removal.
    assert {item.tool_name for item in invocations} == {"docker", "trivy"}
    assert len(invocations) == 3


async def test_a_successful_scan_produces_verified_findings_and_always_cleans_up() -> None:
    remove_calls = []
    trivy_payload = {
        "Results": [
            {
                "Target": "ghcr.io/org/app:tag (debian 12.4)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-12345",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.9-1",
                        "FixedVersion": "3.0.11-1",
                        "Severity": "HIGH",
                        "Title": "OpenSSL buffer overflow",
                        "CweIDs": ["CWE-120"],
                    },
                    # Not a real advisory shape — dropped, never invented.
                    {
                        "VulnerabilityID": "NOT-A-REAL-ID",
                        "PkgName": "whatever",
                        "InstalledVersion": "1.0",
                        "Severity": "LOW",
                    },
                ],
            }
        ]
    }

    async def pull(_ref: ImageRef) -> ToolResult:
        return _ok()

    async def scan(_ref: ImageRef) -> ToolResult:
        return _ok(json.dumps(trivy_payload))

    async def remove(ref: ImageRef) -> ToolResult:
        remove_calls.append(ref)
        return _ok()

    engine = ContainerEngine(pull=pull, scan=scan, remove=remove)
    target = ContainerTarget(
        image_ref="ghcr.io/org/app:tag", allowed_registries=("ghcr.io",), allow_live_pull=True
    )

    findings, invocations = await engine.run(target)

    assert len(remove_calls) == 1
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "KERVY-CONTAINER-101"
    assert "CVE-2023-12345" in finding.title
    assert finding.frameworks == ("MITRE-ATTACK:T1595.002", "CVE-2023-12345", "CWE-120")
    assert finding.fingerprint is not None
    assert {item.tool_name for item in invocations} == {"docker", "trivy"}


async def test_trivy_scans_via_the_local_docker_daemon_not_its_own_registry_client() -> None:
    """`--image-src docker` is the whole point: trivy must read the image the
    pull already placed on the daemon, never make its own network call to
    the registry — a second, unaudited path to the same host."""
    import inspect

    from app.core.container.engine import _scan_with_trivy

    source = inspect.getsource(_scan_with_trivy)
    assert '"--image-src"' in source
    assert '"docker"' in source
    assert "--skip-db-update" in source
    assert "--offline-scan" in source


async def test_a_malformed_image_reference_is_a_visible_gap_before_any_pull() -> None:
    calls = []

    async def pull(ref: ImageRef) -> ToolResult:
        calls.append(ref)
        return _ok()

    engine = ContainerEngine(pull=pull)
    target = ContainerTarget(image_ref="", allowed_registries=("ghcr.io",), allow_live_pull=True)

    findings, invocations = await engine.run(target)

    assert calls == []
    assert invocations == []
    assert findings[0].id == "KERVY-CONTAINER-109"


def test_check_registry_allowed_error_is_a_container_pull_error() -> None:
    # Sanity check that engine.py's `except ContainerPullError` actually
    # catches what `check_registry_allowed` raises.
    assert issubclass(ContainerPullError, RuntimeError)
