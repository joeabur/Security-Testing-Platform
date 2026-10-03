"""The `kervy-ai` CLI (docs/BUILD_SPEC.md §20, §26 Phase 10).

Phase 10's acceptance criterion has two halves: "the CLI exercises the same
API/scope engine as the UI (no parallel weaker path)", and "a seeded critical
finding fails the gate with the documented exit code". Both are asserted here
— the first structurally, by checking what the CLI is allowed to import, and
the second by running the gate command against a mocked API.
"""

import json
import pathlib
import re

import httpx
import pytest
import respx

from app.core.gate.model import ExitCode
from kervy_cli import main as cli
from kervy_cli.client import ApiClient, CliError
from kervy_cli.config import Profile

BASE_URL = "http://platform.test/api/v1"
ORG = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"


@pytest.fixture
def profile(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Profile:
    monkeypatch.setenv("KERVY_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("KERVY_BASE_URL", BASE_URL)
    monkeypatch.setenv("KERVY_API_KEY", "kervy_0011223344556677_secret-value")
    monkeypatch.setenv("KERVY_ORGANIZATION", ORG)
    return Profile.load()


def _finding(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "fingerprint": "sha256:" + "1" * 64,
        "title": "Direct prompt injection overrides the system instruction",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "stability": "deterministic",
        "status": "new",
    }
    base.update(overrides)
    return base


# --- the structural half: no parallel path to the engine ------------------


def test_the_cli_cannot_reach_the_scope_engine_or_a_probe() -> None:
    """The reason the CLI is its own package.

    §26 Phase 10 requires the CLI to exercise the same scope engine as the UI
    rather than a weaker path of its own. The strongest way to guarantee that
    is for the CLI to have no way to reach a target at all except by asking
    the API — so it may import the gate (pure logic over findings the API
    returned) and the shared enums, and nothing else from `app.core`.
    """
    root = pathlib.Path(cli.__file__).resolve().parent
    allowed = {"app.core.gate", "app.core.probes.models"}
    pattern = re.compile(r"^\s*(?:from|import)\s+(app\.[\w.]+)", re.MULTILINE)

    offenders: list[str] = []
    for path in root.rglob("*.py"):
        for module in pattern.findall(path.read_text(encoding="utf-8")):
            if not any(module == item or module.startswith(item + ".") for item in allowed):
                offenders.append(f"{path.name}: {module}")

    assert offenders == [], (
        "the CLI must reach a target only through the REST API; these imports "
        f"would give it a second path: {offenders}"
    )


def test_the_cli_constructs_no_scope_gated_transport() -> None:
    """A belt-and-braces companion to the import check: even a dynamic import
    would have to name one of these."""
    root = pathlib.Path(cli.__file__).resolve().parent
    forbidden = ("GatedTransport", "ScopeEngine", "run_ai_probe", "appsec_engines")
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for name in forbidden:
            assert name not in text, f"{path.name} names {name}"


# --- the gate half --------------------------------------------------------


@respx.mock
def test_a_seeded_critical_finding_fails_the_gate_with_exit_code_1(profile: Profile) -> None:
    respx.get(f"{BASE_URL}/organizations/{ORG}/findings").mock(
        return_value=httpx.Response(200, json=[_finding()])
    )

    code = cli.main(["gate", "--run", RUN])

    assert code == int(ExitCode.GATE_FAILED) == 1


@respx.mock
def test_a_clean_run_passes_the_gate(profile: Profile) -> None:
    respx.get(f"{BASE_URL}/organizations/{ORG}/findings").mock(
        return_value=httpx.Response(200, json=[])
    )
    assert cli.main(["gate", "--run", RUN]) == int(ExitCode.PASS)


@respx.mock
def test_the_gate_asks_only_for_the_run_it_is_gating(profile: Profile) -> None:
    """Gating on the organization's whole backlog would fail a build for
    something a different team has open."""
    route = respx.get(f"{BASE_URL}/organizations/{ORG}/findings").mock(
        return_value=httpx.Response(200, json=[])
    )

    cli.main(["gate", "--run", RUN])

    assert route.calls.last.request.url.params["run_id"] == RUN


@respx.mock
def test_the_gate_prints_what_it_skipped(
    profile: Profile, capsys: pytest.CaptureFixture[str]
) -> None:
    """§23: a gate nobody can argue with is a gate people bypass. "Why did
    this not fail?" has to be answerable from the CI log alone."""
    respx.get(f"{BASE_URL}/organizations/{ORG}/findings").mock(
        return_value=httpx.Response(
            200,
            json=[
                _finding(stability="single_shot", title="Flaky injection"),
                _finding(
                    fingerprint="sha256:" + "2" * 64,
                    severity="MEDIUM",
                    confidence="LOW",
                    title="Low confidence thing",
                ),
            ],
        )
    )

    assert cli.main(["gate", "--run", RUN]) == int(ExitCode.PASS)

    printed = capsys.readouterr().out
    assert "security gate: PASS" in printed
    assert "not counted (2)" in printed
    assert "Flaky injection" in printed
    assert "One observation is not a measurement" in printed


@respx.mock
def test_a_gate_config_file_is_honoured(profile: Profile, tmp_path: pathlib.Path) -> None:
    config = tmp_path / "security-gate.yaml"
    # `fail_on` and the count limits are independent: relaxing the severity
    # list is not enough on its own, because `max_high` still defaults to 0.
    config.write_text(
        "security_gate:\n  fail_on: [critical]\n  max_high: null\n  max_medium: null\n",
        encoding="utf-8",
    )
    respx.get(f"{BASE_URL}/organizations/{ORG}/findings").mock(
        return_value=httpx.Response(200, json=[_finding(severity="HIGH")])
    )

    assert cli.main(["gate", "--run", RUN, "--config", str(config)]) == int(ExitCode.PASS)


def test_a_bad_gate_config_exits_two_not_zero(profile: Profile, tmp_path: pathlib.Path) -> None:
    """A misconfigured gate must never be reported as a pass."""
    config = tmp_path / "security-gate.yaml"
    config.write_text("security_gate:\n  max_hihg: 0\n", encoding="utf-8")

    assert cli.main(["gate", "--run", RUN, "--config", str(config)]) == int(ExitCode.CONFIG_ERROR)


# --- the quality-gate report ------------------------------------------------


@respx.mock
def test_the_report_flag_writes_json_packaging_the_same_decision(
    profile: Profile, tmp_path: pathlib.Path
) -> None:
    respx.get(f"{BASE_URL}/organizations/{ORG}/findings").mock(
        return_value=httpx.Response(200, json=[_finding()])
    )
    report_path = tmp_path / "quality-gate.json"

    code = cli.main(["gate", "--run", RUN, "--report", str(report_path)])

    assert code == int(ExitCode.GATE_FAILED)
    payload = json.loads(report_path.read_text())
    assert payload["passed"] is False
    assert payload["priority_counts"]["P0"] == 1
    assert payload["blocking"][0]["priority"] == "P0"


@respx.mock
def test_the_report_flag_writes_markdown_by_extension(
    profile: Profile, tmp_path: pathlib.Path
) -> None:
    respx.get(f"{BASE_URL}/organizations/{ORG}/findings").mock(
        return_value=httpx.Response(200, json=[_finding()])
    )
    report_path = tmp_path / "quality-gate.md"

    cli.main(["gate", "--run", RUN, "--report", str(report_path)])

    markdown = report_path.read_text()
    assert "FAIL" in markdown
    assert "P0" in markdown


@respx.mock
def test_an_unrecognised_report_extension_is_a_configuration_error(
    profile: Profile, tmp_path: pathlib.Path
) -> None:
    respx.get(f"{BASE_URL}/organizations/{ORG}/findings").mock(
        return_value=httpx.Response(200, json=[])
    )
    report_path = tmp_path / "quality-gate.txt"

    assert cli.main(["gate", "--run", RUN, "--report", str(report_path)]) == int(
        ExitCode.CONFIG_ERROR
    )
    assert not report_path.exists()


# --- exit codes for refusals ----------------------------------------------


@respx.mock
@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (401, ExitCode.AUTH_ERROR),
        (403, ExitCode.AUTH_ERROR),
        (409, ExitCode.SCOPE_VIOLATION),
        (404, ExitCode.CONFIG_ERROR),
        (422, ExitCode.CONFIG_ERROR),
        (500, ExitCode.CONFIG_ERROR),
    ],
)
def test_an_api_refusal_maps_to_its_documented_exit_code(
    profile: Profile, status_code: int, expected: ExitCode
) -> None:
    """§20: CI has to tell "found issues" apart from "refused to run"."""
    respx.get(f"{BASE_URL}/organizations/{ORG}/findings").mock(
        return_value=httpx.Response(status_code, json={"error": {"message": "nope"}})
    )

    assert cli.main(["findings", "list"]) == int(expected)


def test_no_credential_means_exit_three_not_a_crash(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KERVY_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("KERVY_BASE_URL", BASE_URL)
    monkeypatch.delenv("KERVY_API_KEY", raising=False)
    monkeypatch.setenv("KERVY_ORGANIZATION", ORG)

    assert cli.main(["findings", "list"]) == int(ExitCode.AUTH_ERROR)


def test_no_organization_is_a_configuration_error(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KERVY_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("KERVY_API_KEY", "kervy_0011223344556677_secret")
    monkeypatch.delenv("KERVY_ORGANIZATION", raising=False)

    assert cli.main(["findings", "list"]) == int(ExitCode.CONFIG_ERROR)


@respx.mock
def test_an_unreachable_platform_is_a_configuration_error(profile: Profile) -> None:
    respx.get(f"{BASE_URL}/organizations/{ORG}/findings").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    assert cli.main(["findings", "list"]) == int(ExitCode.CONFIG_ERROR)


# --- target configuration --------------------------------------------------
#
# `target add` only creates the target itself; rules of engagement, the
# adapter, the code scope and the runtime-protection declaration are each a
# separate PUT the API exposes as its own resource (docs/cicd.md's own
# workflow assumes a target is already configured before the CI commands
# run). Found missing entirely during a live audit: `target add`, `auth
# grant` and `scope explain/validate` existed, but nothing wrapped these
# four PUT endpoints, so a security-engineer-scoped CLI/API-key user had no
# sanctioned way to finish configuring a target short of raw HTTP.


@respx.mock
def test_target_roe_puts_the_yaml_body(profile: Profile, tmp_path: pathlib.Path) -> None:
    target = "33333333-3333-3333-3333-333333333333"
    config = tmp_path / "roe.yaml"
    config.write_text("allowed_domains: ['127.0.0.1']\nsafe_mode: true\n")
    route = respx.put(f"{BASE_URL}/organizations/{ORG}/targets/{target}/rules-of-engagement").mock(
        return_value=httpx.Response(200, json={"target_id": target, "safe_mode": True})
    )

    code = cli.main(["target", "roe", "--target", target, "--file", str(config)])

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {
        "allowed_domains": ["127.0.0.1"],
        "safe_mode": True,
    }


@respx.mock
def test_target_adapter_puts_the_yaml_body(profile: Profile, tmp_path: pathlib.Path) -> None:
    target = "33333333-3333-3333-3333-333333333333"
    config = tmp_path / "adapter.yaml"
    config.write_text("adapter_kind: chat_http\nadapter_config:\n  endpoint: /api/chat\n")
    route = respx.put(f"{BASE_URL}/organizations/{ORG}/targets/{target}/adapter").mock(
        return_value=httpx.Response(200, json={"id": target, "adapter_kind": "chat_http"})
    )

    code = cli.main(["target", "adapter", "--target", target, "--file", str(config)])

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {
        "adapter_kind": "chat_http",
        "adapter_config": {"endpoint": "/api/chat"},
    }


@respx.mock
def test_target_code_puts_the_yaml_body(profile: Profile, tmp_path: pathlib.Path) -> None:
    target = "33333333-3333-3333-3333-333333333333"
    config = tmp_path / "code.yaml"
    config.write_text(
        "repo_ref: git+https://example.test/repo.git#main\n"
        "code_scope:\n  allowed_paths: ['src/**']\n"
    )
    route = respx.put(f"{BASE_URL}/organizations/{ORG}/targets/{target}/code").mock(
        return_value=httpx.Response(200, json={"id": target})
    )

    code = cli.main(["target", "code", "--target", target, "--file", str(config)])

    assert code == 0
    assert route.calls.last.request.method == "PUT"


@respx.mock
def test_target_runtime_protection_puts_the_yaml_body(
    profile: Profile, tmp_path: pathlib.Path
) -> None:
    target = "33333333-3333-3333-3333-333333333333"
    config = tmp_path / "rp.yaml"
    config.write_text("controls: []\n")
    route = respx.put(f"{BASE_URL}/organizations/{ORG}/targets/{target}/runtime-protection").mock(
        return_value=httpx.Response(200, json={"id": target})
    )

    code = cli.main(["target", "runtime-protection", "--target", target, "--file", str(config)])

    assert code == 0
    assert route.calls.last.request.method == "PUT"


# --- repositories -----------------------------------------------------------
#
# The fast path onto code scanning: `repo add` posts flags as JSON, not a
# YAML file like `target add` — matching the API's own design decision to
# skip the Rules-of-Engagement/Authorization workflow for a repository.


@respx.mock
def test_repo_add_posts_the_url_and_authorized_flag(profile: Profile) -> None:
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/repositories").mock(
        return_value=httpx.Response(
            201, json={"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "name": "Example"}
        )
    )

    code = cli.main(
        [
            "repo",
            "add",
            "--name",
            "Example",
            "--url",
            "https://example.test/org/repo.git",
            "--branch",
            "main",
            "--authorized",
        ]
    )

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {
        "name": "Example",
        "url": "https://example.test/org/repo.git",
        "branch": "main",
        "authorized": True,
    }


def test_repo_add_without_authorized_refuses_before_any_request(profile: Profile) -> None:
    """Client-side, before the request is even built: the same requirement
    the API enforces server-side, checked here so a scripted call fails
    fast with a clear message rather than a generic 422."""
    code = cli.main(
        ["repo", "add", "--name", "Example", "--url", "https://example.test/org/repo.git"]
    )

    assert code == int(ExitCode.CONFIG_ERROR)


@respx.mock
def test_repo_scan_posts_safe_mode_from_the_unsafe_flag(profile: Profile) -> None:
    repo = "44444444-4444-4444-4444-444444444444"
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/repositories/{repo}/scan").mock(
        return_value=httpx.Response(200, json={"run_id": RUN, "status": "queued"})
    )

    code = cli.main(["repo", "scan", repo, "--unsafe"])

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {"safe_mode": False}


@respx.mock
def test_repo_remove_deletes(profile: Profile) -> None:
    repo = "44444444-4444-4444-4444-444444444444"
    route = respx.delete(f"{BASE_URL}/organizations/{ORG}/repositories/{repo}").mock(
        return_value=httpx.Response(204)
    )

    code = cli.main(["repo", "remove", repo])

    assert code == 0
    assert route.calls.last.request.method == "DELETE"


# --- scope explain --------------------------------------------------------


@respx.mock
def test_a_refused_url_exits_four(profile: Profile) -> None:
    """So a pipeline can check its scope configuration without scanning."""
    target = "33333333-3333-3333-3333-333333333333"
    respx.post(f"{BASE_URL}/organizations/{ORG}/targets/{target}/scope/explain").mock(
        return_value=httpx.Response(200, json={"allowed": False, "rule": "domain_not_allowlisted"})
    )

    code = cli.main(["scope", "explain", target, "--url", "https://evil.test/"])

    assert code == int(ExitCode.SCOPE_VIOLATION)


@respx.mock
def test_an_allowed_url_exits_zero(profile: Profile) -> None:
    target = "33333333-3333-3333-3333-333333333333"
    respx.post(f"{BASE_URL}/organizations/{ORG}/targets/{target}/scope/explain").mock(
        return_value=httpx.Response(200, json={"allowed": True, "rule": "allowed"})
    )
    assert cli.main(["scope", "explain", target, "--url", "https://ok.test/"]) == 0


# --- evidence -------------------------------------------------------------


@respx.mock
def test_broken_evidence_is_a_failure_not_information(profile: Profile) -> None:
    """If the chain does not verify, the report resting on it cannot be
    trusted, and a pipeline should hear about it."""
    respx.get(f"{BASE_URL}/organizations/{ORG}/runs/{RUN}/evidence/verify").mock(
        return_value=httpx.Response(
            200, json={"ok": False, "entries": 3, "problems": ["entry 1: chain broken"]}
        )
    )

    assert cli.main(["evidence", "verify", "--run", RUN]) == int(ExitCode.GATE_FAILED)


# --- API keys ---------------------------------------------------------------


@respx.mock
def test_apikey_create_posts_name_and_scopes(
    profile: Profile, capsys: pytest.CaptureFixture[str]
) -> None:
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/api-keys").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "name": "ci-pipeline",
                "key_id": "00112233",
                "scopes": ["read", "scan"],
                "role": "SECURITY_ENGINEER",
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": None,
                "last_used_at": None,
                "revoked_at": None,
                "token": "kervy_00112233_secret",  # pragma: allowlist secret
            },
        )
    )

    code = cli.main(
        ["apikey", "create", "--name", "ci-pipeline", "--scope", "read", "--scope", "scan"]
    )

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {
        "name": "ci-pipeline",
        "scopes": ["read", "scan"],
    }
    # The one response that ever carries the token, printed so the caller can
    # save it before it is gone.
    captured = capsys.readouterr()
    assert "kervy_00112233_secret" in captured.out


@respx.mock
def test_apikey_create_with_expiry_puts_it_in_the_body(profile: Profile) -> None:
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/api-keys").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "name": "ci-pipeline",
                "key_id": "00112233",
                "scopes": ["read"],
                "role": "VIEWER",
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": "2026-02-01T00:00:00Z",
                "last_used_at": None,
                "revoked_at": None,
                "token": "kervy_00112233_secret",  # pragma: allowlist secret
            },
        )
    )

    code = cli.main(
        [
            "apikey",
            "create",
            "--name",
            "ci-pipeline",
            "--scope",
            "read",
            "--expires",
            "2026-02-01T00:00:00Z",
        ]
    )

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {
        "name": "ci-pipeline",
        "scopes": ["read"],
        "expires_at": "2026-02-01T00:00:00Z",
    }


@respx.mock
def test_apikey_list_gets_the_collection(profile: Profile) -> None:
    respx.get(f"{BASE_URL}/organizations/{ORG}/api-keys").mock(
        return_value=httpx.Response(200, json=[])
    )

    assert cli.main(["apikey", "list"]) == 0


@respx.mock
def test_apikey_revoke_posts_to_the_revoke_route(profile: Profile) -> None:
    key_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/api-keys/{key_id}/revoke").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": key_id,
                "name": "ci-pipeline",
                "key_id": "00112233",
                "scopes": ["read"],
                "role": "VIEWER",
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": None,
                "last_used_at": None,
                "revoked_at": "2026-01-02T00:00:00Z",
            },
        )
    )

    code = cli.main(["apikey", "revoke", key_id])

    assert code == 0
    assert route.calls.last.request.method == "POST"


# --- assistant drafts -------------------------------------------------------


@respx.mock
def test_assist_status_gets_the_status_endpoint(profile: Profile) -> None:
    respx.get(f"{BASE_URL}/organizations/{ORG}/assistant/status").mock(
        return_value=httpx.Response(200, json={"configured": True, "autonomy_mode": "RECOMMEND"})
    )

    assert cli.main(["assist", "status"]) == 0


@respx.mock
def test_assist_draft_posts_the_field_and_scan_result(profile: Profile) -> None:
    scan_result = "55555555-5555-5555-5555-555555555555"
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/assistant/runs/{RUN}/drafts").mock(
        return_value=httpx.Response(
            201, json={"id": "d1", "field": "remediation", "content": "..."}
        )
    )

    code = cli.main(
        [
            "assist",
            "draft",
            "--run",
            RUN,
            "--field",
            "remediation",
            "--scan-result",
            scan_result,
        ]
    )

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {
        "field": "remediation",
        "scan_result_id": scan_result,
    }


@respx.mock
def test_assist_draft_run_summary_omits_scan_result(profile: Profile) -> None:
    """`run_summary` is the one field that needs no `scan_result_id` — the
    CLI must not send a null placeholder for it."""
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/assistant/runs/{RUN}/drafts").mock(
        return_value=httpx.Response(201, json={"id": "d1", "field": "run_summary"})
    )

    code = cli.main(["assist", "draft", "--run", RUN, "--field", "run_summary"])

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {"field": "run_summary"}


@respx.mock
def test_assist_accept_posts_to_the_draft(profile: Profile) -> None:
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/assistant/drafts/d1/accept").mock(
        return_value=httpx.Response(200, json={"id": "d1", "accepted_at": "2026-01-01T00:00:00Z"})
    )

    code = cli.main(["assist", "accept", "d1"])

    assert code == 0
    assert route.calls.last.request.method == "POST"


# --- workflows --------------------------------------------------------------


@respx.mock
def test_workflow_create_posts_the_gate_config_file_and_schedule(
    profile: Profile, tmp_path: pathlib.Path
) -> None:
    target = "33333333-3333-3333-3333-333333333333"
    gate_config = tmp_path / "gate.json"
    gate_config.write_text(json.dumps({"fail_on": ["critical"]}))
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/workflows").mock(
        return_value=httpx.Response(201, json={"id": "w1", "name": "main branch"})
    )

    code = cli.main(
        [
            "workflow",
            "create",
            "--name",
            "main branch",
            "--target",
            target,
            "--trigger-kind",
            "schedule",
            "--gate-config",
            str(gate_config),
            "--schedule-minutes",
            "60",
        ]
    )

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {
        "name": "main branch",
        "target_id": target,
        "trigger_kind": "schedule",
        "enabled": True,
        "gate_config": {"fail_on": ["critical"]},
        "schedule_interval_minutes": 60,
    }


def test_workflow_update_enable_and_disable_are_mutually_exclusive(profile: Profile) -> None:
    """argparse itself refuses this combination before any request is
    built — a usage error, exiting the same code a configuration error
    does."""
    with pytest.raises(SystemExit) as caught:
        cli.main(["workflow", "update", "w1", "--enable", "--disable"])
    assert caught.value.code == int(ExitCode.CONFIG_ERROR)


@respx.mock
def test_workflow_update_disable_patches_enabled_false(profile: Profile) -> None:
    route = respx.patch(f"{BASE_URL}/organizations/{ORG}/workflows/w1").mock(
        return_value=httpx.Response(200, json={"id": "w1", "enabled": False})
    )

    code = cli.main(["workflow", "update", "w1", "--disable"])

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {"enabled": False}


@respx.mock
def test_workflow_delete_deletes(profile: Profile) -> None:
    route = respx.delete(f"{BASE_URL}/organizations/{ORG}/workflows/w1").mock(
        return_value=httpx.Response(204)
    )

    code = cli.main(["workflow", "delete", "w1"])

    assert code == 0
    assert route.calls.last.request.method == "DELETE"


@respx.mock
def test_workflow_trigger_posts_ref_commit_and_pull_number(profile: Profile) -> None:
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/workflows/w1/runs").mock(
        return_value=httpx.Response(201, json={"id": "wr1", "status": "completed"})
    )

    code = cli.main(
        [
            "workflow",
            "trigger",
            "w1",
            "--ref",
            "refs/heads/main",
            "--commit",
            "deadbeef",
            "--pull-number",
            "7",
        ]
    )

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {
        "ref": "refs/heads/main",
        "commit": "deadbeef",
        "pull_number": 7,
    }


@respx.mock
def test_workflow_webhook_secret_is_a_post_with_no_body(profile: Profile) -> None:
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/workflows/w1/webhook-secret").mock(
        return_value=httpx.Response(
            200,
            json={
                "secret": "whsec_example",  # pragma: allowlist secret
                "webhook_url": "https://x/webhooks/w1",
            },
        )
    )

    code = cli.main(["workflow", "webhook-secret", "w1"])

    assert code == 0
    assert route.calls.last.request.method == "POST"


@respx.mock
def test_workflow_approve_posts_to_the_paused_run(profile: Profile) -> None:
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/workflows/w1/runs/wr1/approve").mock(
        return_value=httpx.Response(200, json={"id": "wr1", "status": "completed"})
    )

    code = cli.main(["workflow", "approve", "w1", "--run", "wr1"])

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {}


@respx.mock
def test_workflow_reject_requires_a_reason_and_posts_it(profile: Profile) -> None:
    route = respx.post(f"{BASE_URL}/organizations/{ORG}/workflows/w1/runs/wr1/reject").mock(
        return_value=httpx.Response(200, json={"id": "wr1", "status": "rejected"})
    )

    code = cli.main(["workflow", "reject", "w1", "--run", "wr1", "--reason", "not this week"])

    assert code == 0
    assert json.loads(route.calls.last.request.content) == {"reason": "not this week"}


# --- profile handling -----------------------------------------------------


def test_login_writes_an_owner_only_config(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KERVY_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("KERVY_API_KEY", raising=False)

    with respx.mock:
        # login now fetches the pre-session CSRF cookie first
        # (app/core/csrf/anon.py) and echoes it back on the POST.
        respx.get(f"{BASE_URL}/auth/csrf").mock(
            return_value=httpx.Response(
                204, headers=[("set-cookie", "kervy_csrf_anon=anon-token-value; Path=/")]
            )
        )
        respx.post(f"{BASE_URL}/auth/login").mock(
            return_value=httpx.Response(200, json={"access_token": "jwt-token"})
        )
        code = cli.main(
            [
                "login",
                "--email",
                "operator@example.test",
                "--password",
                "hunter2-but-long-enough",
                "--base-url",
                BASE_URL,
            ]
        )

    assert code == 0
    path = tmp_path / "config.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["token"] == "jwt-token"  # pragma: allowlist secret
    # A credential readable by every account on the machine has already leaked.
    assert path.stat().st_mode & 0o077 == 0


def test_a_corrupt_config_does_not_stop_the_cli(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("KERVY_CONFIG", str(path))
    monkeypatch.setenv("KERVY_API_KEY", "kervy_0011223344556677_secret")

    loaded = Profile.load()
    assert loaded.token == "kervy_0011223344556677_secret"  # pragma: allowlist secret


def test_no_command_prints_help_and_exits_two() -> None:
    assert cli.main([]) == int(ExitCode.CONFIG_ERROR)


def test_the_client_refuses_to_send_an_unauthenticated_request() -> None:
    with pytest.raises(CliError) as caught:
        ApiClient(BASE_URL, None).request("GET", "/organizations")
    assert caught.value.exit_code is ExitCode.AUTH_ERROR
