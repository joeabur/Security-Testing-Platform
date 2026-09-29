"""Runtime-protection extension points (docs/BUILD_SPEC.md §26 Phase 18, §4.5 row 6).

The acceptance criterion has three clauses, and each gets a test that fails if
the clause stops being true:

1. *A RASP-effectiveness engine can be added without touching the orchestrator
   or the scope engine.* Asserted by checking the contract depends on neither.
2. *No RASP agent ships.* Asserted structurally — nothing in this repository
   instruments a process, and nothing implements the engine protocol.
3. *A static check proves no unsafe-mode path exists for that interface.*
   Asserted by walking the context's fields and the protocol's signatures.

The fourth thing this file protects is subtler and matters more: a claim must
never be storable as a measurement. Nothing here measures runtime protection,
so nothing here may produce a control marked `observed`.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import re
import uuid
from dataclasses import fields

import pytest
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.rasp import contract
from app.core.rasp.contract import (
    RUNTIME_PROTECTION_ENGINES,
    ClaimedControl,
    ControlKind,
    Evidenced,
    RuntimeProtectionContext,
    RuntimeProtectionEngine,
    RuntimeProtectionProfile,
    untested_marker,
)

APP = pathlib.Path(__file__).resolve().parents[1] / "app"


# --------------------------------------------------------------------------
# Clause 3: no unsafe-mode path.
# --------------------------------------------------------------------------

#: Field-name fragments that would let a caller weaken a control. Matched as
#: substrings on purpose: `allow_state_mutation_for_rasp` is as much a problem
#: as `allow`, and a test that only rejected exact names would be defeated by
#: a prefix.
_RELAXING = (
    "safe_mode",
    "unsafe",
    "force",
    "allow_",
    "bypass",
    "disable",
    "skip_",
    "ignore_scope",
    "override",
    "insecure",
    "verify_ssl",
    "no_verify",
)


def test_the_context_has_no_field_that_could_relax_a_control() -> None:
    """The §26 Phase 18 static check, on the interface itself.

    A RASP engine is the most tempting place on this platform to add a
    "just for this run" escape hatch: measuring whether a WAF blocks something
    sounds like it needs to send something a WAF would block. It does not need
    a flag — it needs the engagement to authorize the request, which is what
    the rules of engagement already decide.

    Verified by adding `safe_mode: bool = False` to `RuntimeProtectionContext`
    and watching this fail.
    """
    offenders = [
        item.name
        for item in fields(RuntimeProtectionContext)
        if any(fragment in item.name.lower() for fragment in _RELAXING)
    ]
    assert offenders == [], (
        f"RuntimeProtectionContext declares {offenders}, which would give a "
        "runtime-protection engine a way to relax a control. An engine reaches a "
        "target through the run's scope-gated transport under the run's rules of "
        "engagement; there is no flag for doing otherwise."
    )


def test_the_engine_protocol_takes_nothing_but_the_context() -> None:
    """No second parameter can smuggle in a transport, a URL or a flag.

    `applies_to` and `run` take the context and nothing else. A `transport=`
    parameter would be an ungated HTTP path by another name.
    """
    for name in ("applies_to", "run"):
        signature = inspect.signature(getattr(RuntimeProtectionEngine, name))
        parameters = [p for p in signature.parameters if p != "self"]
        assert parameters == ["context"], (
            f"RuntimeProtectionEngine.{name} takes {parameters}; it must take the "
            "context alone, so an engine cannot be handed its own transport."
        )


def test_the_contract_imports_neither_the_orchestrator_nor_the_scope_engine() -> None:
    """Clause 1, read from the imports rather than asserted in prose.

    If the extension point depended on either, adding an engine would mean
    editing them — which is exactly what the criterion says must not be
    necessary. Parsed with `ast` rather than grepped, because the module's own
    docstring says the words "orchestrator" and "scope engine" repeatedly and
    a grep would match its explanation of the rule.
    """
    source = pathlib.Path(contract.__file__).read_text()
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    forbidden = sorted(
        name
        for name in imported
        if name.startswith(("app.core.orchestrator", "app.core.scope", "app.workers"))
    )
    assert forbidden == [], (
        f"app/core/rasp/contract.py imports {forbidden}. The extension point must "
        "not depend on the orchestrator or the scope engine, or adding an engine "
        "would mean editing them."
    )


# --------------------------------------------------------------------------
# Clause 2: no agent ships.
# --------------------------------------------------------------------------

#: How a RASP agent gets into a process. Any of these appearing in executable
#: code under `app/` would mean this project ships something designed to run
#: inside somebody else's application — the one thing §2 forbids outright.
_INSTRUMENTATION = (
    "sys.meta_path",
    "sys.path_hooks",
    "sys.setprofile",
    "sys.settrace",
    "threading.settrace",
    "sitecustomize",
    "usercustomize",
    "ctypes.CDLL",
    "ctypes.cdll",
    "LD_PRELOAD",
    "PYTHONSTARTUP",
)


def _executable_source(tree: ast.AST) -> str:
    """Everything in a module except its docstrings.

    Necessary, not fastidious. `app/core/rasp/contract.py` explains the rule
    this test enforces, and naming `sitecustomize` in that explanation is not
    shipping one. A plain substring scan over the file matched its own
    docstring — the same mistake that made an earlier boundary test in this
    project pass for the wrong reason — so docstrings come out first and the
    scan runs over what actually executes.
    """
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                # Both the statement and the string it wraps: `ast.walk`
                # yields the inner Constant independently, so skipping only
                # the Expr leaves the prose in.
                docstrings.add(id(body[0]))
                docstrings.add(id(body[0].value))

    pieces: list[str] = []
    for node in ast.walk(tree):
        if id(node) in docstrings:
            continue
        if isinstance(node, ast.Attribute | ast.Name | ast.Constant):
            try:
                pieces.append(ast.unparse(node))
            except Exception:
                continue
    return "\n".join(pieces)


def test_no_process_instrumentation_ships_anywhere_in_the_application() -> None:
    """No agent, no bootstrap, no import hook, no monkey-patch.

    Scans every Python file under `app/` rather than only `app/core/rasp/`:
    the rule is about the product, not about one package, and an agent would
    not announce itself by living in the directory named after the thing it
    must not be. Also checks no file is *named* `sitecustomize.py`, which is
    how one would be loaded without any code referencing it at all.

    Verified by planting `sys.meta_path.append(_Finder())` in the contract and
    watching this fail — and by confirming it no longer fires on the docstring
    that explains the rule, which is what it did first.
    """
    offenders: list[str] = []
    for path in APP.rglob("*.py"):
        if path.stem in ("sitecustomize", "usercustomize"):
            offenders.append(f"{path.relative_to(APP.parent)}: is a {path.stem} hook")
            continue
        code = _executable_source(ast.parse(path.read_text()))
        for marker in _INSTRUMENTATION:
            if marker in code:
                offenders.append(f"{path.relative_to(APP.parent)}: {marker}")
    assert offenders == [], (
        "process instrumentation found: "
        + "; ".join(offenders)
        + ". This platform does not run inside a customer's process; a RASP agent "
        "is exactly what §4.5 row 6 forbids shipping."
    )


def test_the_instrumentation_scan_reads_code_and_not_prose() -> None:
    """The scan above must have teeth and must not fire on an explanation.

    Both halves matter. A scan that missed real instrumentation would be
    worthless, and one that fired on the docstring describing it would have to
    be deleted the first time somebody documented the rule — which is how a
    control quietly disappears.
    """
    explains = ast.parse('"""We never touch sys.meta_path or ship a sitecustomize."""\n')
    assert "meta_path" not in _executable_source(explains)

    does_it = ast.parse("import sys\nsys.meta_path.append(object())\n")
    assert "sys.meta_path" in _executable_source(does_it)


def test_no_runtime_protection_engine_is_registered() -> None:
    """The registry is empty, and that is the deliverable.

    Phase 18 authorizes the extension point, not an engine. Registering one
    here would be shipping the thing the phase says to defer, so the emptiness
    is asserted rather than assumed — and a future phase that adds an engine
    has to change this test deliberately.
    """
    assert RUNTIME_PROTECTION_ENGINES == ()


def test_nothing_in_the_application_implements_the_engine_protocol() -> None:
    """An unregistered engine would still be a shipped engine.

    `RUNTIME_PROTECTION_ENGINES` being empty only proves nothing is *wired in*.
    This reads every class under `app/` and fails on any that would satisfy the
    protocol: an `async run` whose parameter is annotated
    `RuntimeProtectionContext`.

    Read with `ast` rather than by importing and calling `issubclass`, for two
    reasons. A protocol with non-method members cannot be used with
    `issubclass` at all, and a module that fails to import under test
    conditions would be skipped — an engine hiding behind an optional
    dependency is still an engine. Source is the thing that ships.

    Verified by adding a class with `async def run(self, context:
    RuntimeProtectionContext)` to the contract and watching this fail.
    """
    implementers: list[str] = []
    for path in APP.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            # The protocol itself declares the shape; it is not an engine.
            if any("Protocol" in ast.unparse(base) for base in node.bases):
                continue
            for item in node.body:
                if not isinstance(item, ast.AsyncFunctionDef) or item.name != "run":
                    continue
                annotations = {
                    ast.unparse(arg.annotation) for arg in item.args.args if arg.annotation
                }
                if any("RuntimeProtectionContext" in text for text in annotations):
                    implementers.append(f"{path.relative_to(APP.parent)}:{node.name}")
    assert implementers == [], (
        f"these classes implement RuntimeProtectionEngine: {implementers}. "
        "Phase 18 ships the extension point, not an engine."
    )


# --------------------------------------------------------------------------
# A claim is never a measurement.
# --------------------------------------------------------------------------


def test_a_control_cannot_be_constructed_as_observed() -> None:
    """Nothing here measured anything, so nothing here may say it did.

    `observed` and `not_observed` exist so a future engine has somewhere to put
    a real result. Until one exists, constructing either is a lie the data
    model would carry forever, so it raises.

    Verified by deleting `__post_init__`: this test passes anything.
    """
    assert ClaimedControl(kind=ControlKind.WAF).evidenced is Evidenced.CLAIMED

    for value in (Evidenced.OBSERVED, Evidenced.NOT_OBSERVED):
        with pytest.raises(ValueError, match="no runtime-protection engine exists"):
            ClaimedControl(kind=ControlKind.WAF, evidenced=value)


def test_a_stored_profile_round_trips_and_stays_a_claim() -> None:
    profile = RuntimeProtectionProfile(
        controls=(
            ClaimedControl(kind=ControlKind.WAF, vendor="Example WAF"),
            ClaimedControl(kind=ControlKind.PROMPT_FIREWALL, telemetry_env_var="KERVY_WAF_TOKEN"),
        )
    )
    records = profile.control_records()
    assert [record["evidenced"] for record in records] == ["claimed", "claimed"]

    restored = RuntimeProtectionProfile.from_records(records)
    assert restored.kinds() == (ControlKind.WAF, ControlKind.PROMPT_FIREWALL)
    assert all(control.evidenced is Evidenced.CLAIMED for control in restored.controls)


def test_an_unknown_control_kind_becomes_other_rather_than_breaking_a_target() -> None:
    """A profile written by a newer version must still render on an older one."""
    restored = RuntimeProtectionProfile.from_records(
        [{"kind": "quantum_shield"}, "not a mapping", {"kind": "waf"}]
    )
    assert restored.kinds() == (ControlKind.OTHER, ControlKind.WAF)


# --------------------------------------------------------------------------
# The coverage marker.
# --------------------------------------------------------------------------


def test_a_target_that_declares_nothing_produces_no_marker() -> None:
    """There is no gap to report about a target that claimed nothing."""
    assert untested_marker(RuntimeProtectionProfile()) is None


def test_declared_controls_produce_a_visible_not_tested_line() -> None:
    """§14: a report says what it did not cover.

    Silence about a claimed WAF reads as a WAF that held. This asserts the
    marker names the controls and says plainly that nothing measured them.

    Verified by making `untested_marker` return `None` unconditionally.
    """
    marker = untested_marker(
        RuntimeProtectionProfile(
            controls=(
                ClaimedControl(kind=ControlKind.WAF),
                ClaimedControl(kind=ControlKind.RASP_AGENT, vendor="Example"),
            )
        )
    )
    assert marker is not None
    assert marker.id == "KERVY-RASP-000"
    assert "Not tested" in marker.title
    assert "waf" in marker.evidence and "rasp_agent" in marker.evidence
    assert "claimed" in marker.evidence
    # It must not read as a pass. "Unknown" is the honest impact of a
    # measurement that did not happen.
    assert "Unknown" in marker.impact


def test_the_marker_never_claims_the_controls_work() -> None:
    """The package can say "we did not test this" and cannot say "this works".

    A wording check, which is unusual — but this marker is the only thing in
    the package that reaches a report, and a reader who skims it must not come
    away believing something was verified.

    The patterns are claim-shaped phrases rather than bare words, because the
    first version of this test forbade "effective" and fired on the marker's
    own sentence *"did not measure whether any of it is effective"* — an
    honest statement of the opposite. A test that punishes precise writing
    gets the precise writing removed.
    """
    marker = untested_marker(
        RuntimeProtectionProfile(controls=(ClaimedControl(kind=ControlKind.WAF),))
    )
    assert marker is not None
    prose = " ".join(
        [marker.title, marker.description, marker.impact, marker.evidence, marker.remediation]
    )

    claims = (
        r"\b(?:is|are|was|were)\s+effective\b",
        r"(?<!un)\bverified\b",
        r"\bprotected against\b",
        r"\bmitigated\b",
        r"\bsuccessfully blocked\b",
        r"\bconfirmed\b",
    )
    for pattern in claims:
        assert not re.search(pattern, prose, re.I), (
            f"the not-tested marker matches {pattern!r}, which reads as a result. "
            "Nothing measured these controls."
        )

    # And it must positively say so, rather than merely avoiding the words.
    assert "did not measure" in prose


# --------------------------------------------------------------------------
# The API stores a claim, and only a claim.
# --------------------------------------------------------------------------


async def _setup(
    client: AsyncClient, password: str, suffix: str
) -> tuple[str, str, dict[str, str]]:
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"rasp{suffix}@example.test",
            "full_name": "RASP Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"RASP Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Protected target",
                "environment": "test",
                "kind": "api",
                "base_url": "http://rasp.example.test",
            },
            headers=headers,
        )
    ).json()["id"]
    return org_id, target_id, headers


async def test_declaring_runtime_protection_stores_it_as_a_claim(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/runtime-protection",
        json={
            "controls": [
                {"kind": "waf", "vendor": "Example WAF"},
                {"kind": "prompt_firewall", "telemetry_env_var": "KERVY_WAF_TOKEN"},
            ]
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    stored = response.json()["runtime_protection"]
    assert [item["kind"] for item in stored] == ["waf", "prompt_firewall"]
    assert {item["evidenced"] for item in stored} == {"claimed"}


async def test_a_caller_cannot_assert_a_measurement_through_the_api(
    client: AsyncClient, strong_password: str
) -> None:
    """`evidenced` is not an input field, and an extra key is rejected.

    If a caller could set it, the API would be a way to write "observed" into
    a target's record without anything having observed anything.
    """
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/runtime-protection",
        json={"controls": [{"kind": "waf", "evidenced": "observed"}]},
        headers=headers,
    )
    # Either the extra key is refused outright, or it is dropped — both are
    # acceptable, but the stored value must be `claimed` either way.
    if response.status_code == 200:
        assert {item["evidenced"] for item in response.json()["runtime_protection"]} == {"claimed"}
    else:
        assert response.status_code == 422


async def test_a_telemetry_value_is_rejected_where_a_variable_name_belongs(
    client: AsyncClient, strong_password: str
) -> None:
    """The same rule every credential on this platform follows.

    A URL or a token pasted into `telemetry_env_var` would be a secret in a
    database row, and therefore in every backup and support ticket taken
    afterwards.

    Verified by removing the validator: the URL is stored.
    """
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    for value in ("https://telemetry.example.test/ingest?key=abc123", "sk-live-not-a-name"):
        response = await client.put(
            f"/api/v1/organizations/{org_id}/targets/{target_id}/runtime-protection",
            json={"controls": [{"kind": "waf", "telemetry_env_var": value}]},
            headers=headers,
        )
        assert response.status_code == 422, f"{value!r} was accepted as a variable name"

    target = await client.get(
        f"/api/v1/organizations/{org_id}/targets/{target_id}", headers=headers
    )
    assert target.json()["runtime_protection"] == []


async def test_an_empty_list_clears_the_declaration(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    base = f"/api/v1/organizations/{org_id}/targets/{target_id}/runtime-protection"

    await client.put(base, json={"controls": [{"kind": "waf"}]}, headers=headers)
    cleared = await client.put(base, json={"controls": []}, headers=headers)
    assert cleared.status_code == 200
    assert cleared.json()["runtime_protection"] == []
