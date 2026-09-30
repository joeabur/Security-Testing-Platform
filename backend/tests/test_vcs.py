"""Pull-request publishing (docs/BUILD_SPEC.md §27, docs/pull-requests.md).

Writing into a customer's repository is the most externally-visible thing this
platform does, so most of this file is about the boundary: that the layer
cannot merge, push or edit; that a connection cannot reach a host nobody
sanctioned; that a token never leaves the process; and that a finding GitHub
would silently discard is moved somewhere a reviewer still sees it.
"""

from __future__ import annotations

import ipaddress
import json

import pytest

from app.core.gate.evaluate import evaluate
from app.core.gate.model import GateConfig, GateDecision
from app.core.probes.models import Confidence, Severity
from app.core.scope.transport import Observation
from app.core.vcs.contract import (
    GITHUB_API_HOST,
    MAX_ANNOTATIONS_PER_REQUEST,
    CheckConclusion,
    DiffFile,
    PullRequestRef,
    RepoRef,
    VcsError,
    VcsProvider,
    diff_index,
)
from app.core.vcs.egress import vcs_egress_context
from app.core.vcs.github import GitHubClient, changed_lines
from app.core.vcs.policy import resolve_destination, resolve_enterprise_host
from app.core.vcs.render import (
    PublishableFinding,
    annotations_for,
    check_run_for,
    conclusion_for,
)

TOKEN = "ghp_exampleexampleexampleexample1234"  # pragma: allowlist secret
ENV = {"KERVY_TEST_GH_TOKEN": TOKEN}


def finding(**overrides: object) -> PublishableFinding:
    defaults: dict[str, object] = {
        "fingerprint": "sha256:abc",
        "title": "subprocess with shell=True on caller input",
        "severity": "HIGH",
        "surface": "src/app.py:12",
        "probe_id": "KERVY-SAST-B602",
        "severity_rationale": "Caller-controlled string reaches a shell.",
        "remediation": "Pass a list and drop shell=True.",
        "is_new": True,
    }
    defaults.update(overrides)
    return PublishableFinding(**defaults)  # type: ignore[arg-type]


def passing() -> GateDecision:
    return evaluate([], GateConfig(fail_on=(Severity.CRITICAL,), min_confidence=Confidence.LOW))


# --- policy: where a connection may point -----------------------------------


def test_a_github_connection_is_pinned_to_the_github_api_host() -> None:
    destination = resolve_destination(VcsProvider.GITHUB, "KERVY_TEST_GH_TOKEN", environ=ENV)
    assert destination.host == GITHUB_API_HOST
    assert destination.api_base == f"https://{GITHUB_API_HOST}"


def test_a_github_connection_cannot_be_repointed_by_a_row() -> None:
    """An organization admin picks a repository, not a host."""
    with pytest.raises(VcsError, match="always reaches"):
        resolve_destination(
            VcsProvider.GITHUB,
            "KERVY_TEST_GH_TOKEN",
            api_host="attacker.test",
            environ=ENV,
        )


def test_an_enterprise_host_needs_the_operator_allowlist() -> None:
    with pytest.raises(VcsError, match="KERVY_VCS_ALLOWED_HOSTS"):
        resolve_enterprise_host("git.internal.test")
    assert (
        resolve_enterprise_host("git.internal.test", operator_hosts=["git.internal.test"])
        == "git.internal.test"
    )


def test_an_enterprise_connection_uses_the_server_api_prefix() -> None:
    destination = resolve_destination(
        VcsProvider.GITHUB_ENTERPRISE,
        "KERVY_TEST_GH_TOKEN",
        api_host="git.internal.test",
        operator_hosts=["git.internal.test"],
        environ=ENV,
    )
    assert destination.api_base == "https://git.internal.test/api/v3"


def test_a_missing_token_variable_is_a_refusal_naming_the_variable() -> None:
    with pytest.raises(VcsError) as exc:
        resolve_destination(VcsProvider.GITHUB, "KERVY_TEST_ABSENT", environ={})
    assert "KERVY_TEST_ABSENT" in str(exc.value)
    assert TOKEN not in str(exc.value)


# --- egress: what the scope engine permits ----------------------------------


def test_the_egress_context_allowlists_only_the_api_host() -> None:
    destination = resolve_destination(VcsProvider.GITHUB, "KERVY_TEST_GH_TOKEN", environ=ENV)
    ctx = vcs_egress_context(destination)
    assert ctx.roe.allowed_domains == (GITHUB_API_HOST,)
    assert ctx.roe.allowed_ip_ranges == ()


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
async def test_the_write_verbs_that_would_merge_or_push_are_refused(method: str) -> None:
    """`contract.py` promises this layer never merges, pushes or edits a file.

    The scope engine is what enforces it: those operations need PUT, PATCH or
    DELETE, and the context does not permit them — so the promise survives a
    future contributor adding a method that tries.
    """
    from app.core.scope.engine import ScopeEngine

    class Resolver:
        async def resolve(self, hostname: str) -> list[object]:
            return [ipaddress.ip_address("140.82.121.6")]

    destination = resolve_destination(VcsProvider.GITHUB, "KERVY_TEST_GH_TOKEN", environ=ENV)
    decision = await ScopeEngine().explain(
        vcs_egress_context(destination),
        dns_resolver=Resolver(),
        method=method,
        url=f"https://{GITHUB_API_HOST}/repos/o/r/merges",
    )
    assert not decision.allowed
    assert decision.rule == "method_not_allowed"


@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_read_and_create_are_permitted(method: str) -> None:
    from app.core.scope.engine import ScopeEngine

    class Resolver:
        async def resolve(self, hostname: str) -> list[object]:
            return [ipaddress.ip_address("140.82.121.6")]

    destination = resolve_destination(VcsProvider.GITHUB, "KERVY_TEST_GH_TOKEN", environ=ENV)
    decision = await ScopeEngine().explain(
        vcs_egress_context(destination),
        dns_resolver=Resolver(),
        method=method,
        url=f"https://{GITHUB_API_HOST}/repos/o/r/check-runs",
    )
    assert decision.allowed, decision.reason


async def test_an_enterprise_host_on_an_internal_address_is_still_refused() -> None:
    """Sanctioning a host does not sanction an internal address behind it."""
    from app.core.scope.engine import ScopeEngine

    class InternalResolver:
        async def resolve(self, hostname: str) -> list[object]:
            return [ipaddress.ip_address("10.0.0.7")]

    destination = resolve_destination(
        VcsProvider.GITHUB_ENTERPRISE,
        "KERVY_TEST_GH_TOKEN",
        api_host="git.internal.test",
        operator_hosts=["git.internal.test"],
        environ=ENV,
    )
    decision = await ScopeEngine().explain(
        vcs_egress_context(destination),
        dns_resolver=InternalResolver(),
        method="GET",
        url="https://git.internal.test/api/v3/repos/o/r/pulls/1/files",
    )
    assert not decision.allowed
    assert decision.rule == "blocked_ip"


# --- diff parsing -----------------------------------------------------------


def test_changed_lines_counts_added_lines_in_the_new_file() -> None:
    patch = (
        "@@ -1,4 +1,6 @@\n"
        " import os\n"
        "+import subprocess\n"
        " \n"
        "-def run(cmd):\n"
        "-    os.system(cmd)\n"
        "+def run(cmd):\n"
        "+    subprocess.run(cmd, shell=True)\n"
        "+    return 0\n"
    )
    # Lines 2, 4, 5, 6 of the *new* file. A removed line does not advance the
    # cursor; a context line does.
    assert sorted(changed_lines(patch)) == [2, 4, 5, 6]


def test_a_second_hunk_resets_the_cursor() -> None:
    patch = "@@ -1,1 +1,1 @@\n context\n@@ -20,3 +22,4 @@ def other():\n     pass\n+    extra()\n"
    assert sorted(changed_lines(patch)) == [23]


def test_a_binary_file_has_no_patch_and_no_lines() -> None:
    assert changed_lines(None) == frozenset()
    assert changed_lines("") == frozenset()


def test_the_no_newline_marker_is_not_counted_as_a_line() -> None:
    patch = "@@ -1,1 +1,2 @@\n a\n+b\n\\ No newline at end of file\n"
    assert sorted(changed_lines(patch)) == [2]


# --- rendering --------------------------------------------------------------


def test_a_finding_outside_the_diff_is_not_annotated_but_is_not_lost() -> None:
    """GitHub silently discards an annotation outside the diff, so a finding
    that cannot be anchored moves to the body instead of vanishing."""
    diff = diff_index([DiffFile(path="src/app.py", changed_lines=frozenset({12}))])
    inside = finding(surface="src/app.py:12")
    outside = finding(fingerprint="sha256:def", surface="src/other.py:99")

    anchored, unanchored = annotations_for([inside, outside], diff)
    assert [item.path for item in anchored] == ["src/app.py"]
    assert [item.fingerprint for item in unanchored] == ["sha256:def"]


def test_an_http_surface_is_never_treated_as_a_file_path() -> None:
    """`GET /orders/{id}` is not a file, and anchoring to it would point at a
    path that does not exist."""
    assert finding(surface="GET /orders/{id}").location == (None, None)
    assert finding(surface="src/app.py:12").location == ("src/app.py", 12)
    assert finding(surface="src/app.py").location == ("src/app.py", None)


def test_a_finding_with_no_line_cannot_be_anchored() -> None:
    diff = diff_index([DiffFile(path="src/app.py", changed_lines=frozenset({1, 2}))])
    _, unanchored = annotations_for([finding(surface="src/app.py")], diff)
    assert len(unanchored) == 1


def test_annotations_are_capped_and_the_overflow_moves_to_the_body() -> None:
    lines = frozenset(range(1, 200))
    diff = diff_index([DiffFile(path="src/app.py", changed_lines=lines)])
    findings = [
        finding(fingerprint=f"sha256:{index}", surface=f"src/app.py:{index}")
        for index in range(1, 80)
    ]
    anchored, unanchored = annotations_for(findings, diff)
    assert len(anchored) == MAX_ANNOTATIONS_PER_REQUEST
    assert len(unanchored) == 79 - MAX_ANNOTATIONS_PER_REQUEST
    # Nothing is counted twice or lost.
    assert len(anchored) + len(unanchored) == len(findings)


def test_new_findings_are_annotated_before_pre_existing_ones() -> None:
    lines = frozenset(range(1, 10))
    diff = diff_index([DiffFile(path="src/app.py", changed_lines=lines)])
    old = finding(fingerprint="sha256:old", surface="src/app.py:1", is_new=False)
    new = finding(fingerprint="sha256:new", surface="src/app.py:2", is_new=True)
    anchored, _ = annotations_for([old, new], diff)
    assert anchored[0].start_line == 2


def test_the_summary_separates_new_findings_from_pre_existing_ones() -> None:
    """A change touching one file must not read as having introduced
    everything the repository already had."""
    diff = diff_index([DiffFile(path="src/app.py", changed_lines=frozenset({12}))])
    findings = [
        finding(fingerprint="sha256:new", surface="src/app.py:12"),
        finding(fingerprint="sha256:old", surface="src/old.py:3", is_new=False),
    ]
    request, _, _ = check_run_for(findings, passing(), head_sha="a" * 40, diff=diff)
    assert "1 finding(s) first seen in this run" in request.summary
    assert "1 pre-existing finding(s) also present" in request.summary


def test_a_payload_never_carries_evidence_or_a_secret() -> None:
    diff = diff_index([DiffFile(path="src/app.py", changed_lines=frozenset({12}))])
    leaky = finding(severity_rationale="token AKIAIOSFODNN7EXAMPLE was found in the body")
    request, _, _ = check_run_for([leaky], passing(), head_sha="a" * 40, diff=diff)
    blob = json.dumps(request.as_payload())
    assert "AKIAIOSFODNN7EXAMPLE" not in blob


def test_severity_maps_to_githubs_three_levels_without_inventing_urgency() -> None:
    diff = diff_index([DiffFile(path="src/app.py", changed_lines=frozenset({1, 2, 3}))])
    findings = [
        finding(fingerprint="a", severity="CRITICAL", surface="src/app.py:1"),
        finding(fingerprint="b", severity="MEDIUM", surface="src/app.py:2"),
        finding(fingerprint="c", severity="INFORMATIONAL", surface="src/app.py:3"),
    ]
    anchored, _ = annotations_for(findings, diff)
    assert [item.level for item in anchored] == ["failure", "warning", "notice"]


def test_an_empty_run_is_neutral_not_success() -> None:
    """ "We checked and found nothing" and "nothing was checked" must not look
    the same on a pull request."""
    empty = GateDecision(passed=True, exit_code=0, counts={})  # type: ignore[arg-type]
    assert conclusion_for(empty, findings=0) is CheckConclusion.NEUTRAL
    assert conclusion_for(passing(), findings=3) is CheckConclusion.SUCCESS


def test_a_failed_gate_makes_the_check_run_fail() -> None:
    from app.core.gate.model import GateFinding

    decision = evaluate(
        [
            GateFinding(
                fingerprint="sha256:abc",
                title="t",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                stability="deterministic",
                status="new",
            )
        ],
        GateConfig(fail_on=(Severity.CRITICAL,), min_confidence=Confidence.LOW),
    )
    assert not decision.passed
    request, _, _ = check_run_for([finding()], decision, head_sha="a" * 40, diff={})
    assert request.conclusion is CheckConclusion.FAILURE
    assert "Gate failed" in request.summary


def test_the_check_run_payload_never_asks_for_action_required() -> None:
    """`action_required` invites a human to trigger a remediation that does not
    exist."""
    assert "action_required" not in {item.value for item in CheckConclusion}


# --- the client -------------------------------------------------------------


class FakeTransport:
    """Records requests and replays canned responses, in order."""

    def __init__(self, responses: list[tuple[int, object]]) -> None:
        self._responses = responses
        self.calls: list[dict[str, object]] = []

    async def send(self, ctx: object, **kwargs: object) -> Observation:
        self.calls.append(kwargs)
        status, body = self._responses.pop(0)
        return Observation(
            method=str(kwargs.get("method")),
            url=str(kwargs.get("url")),
            status_code=status,
            headers={},
            elapsed_ms=1.0,
            body=json.dumps(body).encode("utf-8") if body is not None else b"",
        )


def client_for(responses: list[tuple[int, object]]) -> tuple[GitHubClient, FakeTransport]:
    destination = resolve_destination(VcsProvider.GITHUB, "KERVY_TEST_GH_TOKEN", environ=ENV)
    transport = FakeTransport(responses)
    return GitHubClient(destination, transport=transport), transport  # type: ignore[arg-type]


async def test_the_token_travels_in_a_header_and_nowhere_else() -> None:
    api, transport = client_for([(200, [])])
    ctx = vcs_egress_context(
        resolve_destination(VcsProvider.GITHUB, "KERVY_TEST_GH_TOKEN", environ=ENV)
    )
    await api.pull_request_files(
        ctx, PullRequestRef(repo=RepoRef("o", "r"), number=7, head_sha="a" * 40)
    )
    call = transport.calls[0]
    headers = call["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    # Never in the URL: a URL reaches logs, proxies and error strings.
    assert TOKEN not in str(call["url"])


async def test_file_paging_stops_on_a_short_page() -> None:
    page = [{"filename": f"src/{index}.py", "patch": "@@ -1 +1 @@\n+x\n"} for index in range(3)]
    api, transport = client_for([(200, page)])
    ctx = vcs_egress_context(
        resolve_destination(VcsProvider.GITHUB, "KERVY_TEST_GH_TOKEN", environ=ENV)
    )
    files = await api.pull_request_files(
        ctx, PullRequestRef(repo=RepoRef("o", "r"), number=7, head_sha="a" * 40)
    )
    assert len(files) == 3
    # One request, because the page was short — not a second that 404s.
    assert len(transport.calls) == 1


async def test_an_http_error_names_the_status_but_not_the_body() -> None:
    api, transport = client_for([(403, {"message": "Resource not accessible", "token": TOKEN})])
    ctx = vcs_egress_context(
        resolve_destination(VcsProvider.GITHUB, "KERVY_TEST_GH_TOKEN", environ=ENV)
    )
    with pytest.raises(VcsError) as exc:
        await api.pull_request_files(
            ctx, PullRequestRef(repo=RepoRef("o", "r"), number=7, head_sha="a" * 40)
        )
    assert "HTTP 403" in str(exc.value)
    assert TOKEN not in str(exc.value)
    assert "Resource not accessible" not in str(exc.value)


async def test_a_review_is_always_a_comment_never_an_approval() -> None:
    """A scanner must never approve a pull request."""
    api, transport = client_for([(200, {"id": 1})])
    ctx = vcs_egress_context(
        resolve_destination(VcsProvider.GITHUB, "KERVY_TEST_GH_TOKEN", environ=ENV)
    )
    await api.post_review(
        ctx, PullRequestRef(repo=RepoRef("o", "r"), number=7, head_sha="a" * 40), body="hello"
    )
    content = transport.calls[0]["content"]
    assert isinstance(content, bytes)
    assert json.loads(content)["event"] == "COMMENT"


async def test_the_check_run_is_created_with_the_head_sha() -> None:
    api, transport = client_for([(201, {"id": 99, "html_url": "https://example.test/run"})])
    ctx = vcs_egress_context(
        resolve_destination(VcsProvider.GITHUB, "KERVY_TEST_GH_TOKEN", environ=ENV)
    )
    request, _, _ = check_run_for([finding()], passing(), head_sha="b" * 40, diff={})
    outcome = await api.create_check_run(ctx, RepoRef("o", "r"), request)
    assert outcome.posted
    assert outcome.check_run_id == 99
    body = json.loads(transport.calls[0]["content"])  # type: ignore[arg-type]
    assert body["head_sha"] == "b" * 40
    assert body["status"] == "completed"


def test_no_client_method_writes_to_the_repository() -> None:
    """Pinned: there is no merge, push, ref-update or file-write method here,
    and adding one would have to change this test."""
    import inspect

    methods = {
        name
        for name, _ in inspect.getmembers(GitHubClient, inspect.isfunction)
        if not name.startswith("_")
    }
    assert methods == {"pull_request_files", "create_check_run", "post_review"}

    source = inspect.getsource(GitHubClient)
    for forbidden in ("/merge", "/git/refs", 'method="PUT"', 'method="PATCH"', "DELETE"):
        assert forbidden not in source, forbidden
