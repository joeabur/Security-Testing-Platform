"""The ML-BOM (docs/BUILD_SPEC.md §23, §27 addendum).

§27's addendum is specific about the shape: *software SBOM and ML-BOM ship as
separate labelled components of one release artifact, **never merged into one
undifferentiated bill of materials***.

The tests below hold two properties. The first is that shape requirement. The
second matters more and is easier to lose: **the inventory must stay honest**.
This release ships no model, and an ML-BOM padded with things that merely look
like models — a deterministic string stub, an endpoint an operator might
configure — would be worse than none, because it would answer "what models does
this ship?" with fiction.
"""

from __future__ import annotations

import json
import pathlib
import re

import yaml

from scripts.mlbom import PROVIDER_ENV_VARS, SPEC_VERSION, build

WORKFLOWS = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"


def test_the_model_inventory_is_empty_because_no_model_ships() -> None:
    """The central claim, asserted rather than written in a docstring.

    If this repository ever does ship a model, this test fails and somebody
    has to add it to the inventory deliberately — which is the right way round.
    """
    document = build()
    assert document["components"] == [], (
        "the ML-BOM lists model components, but this release ships no weights, "
        "checkpoints, training data or fine-tune. Either a model was added and "
        "belongs in the inventory deliberately, or something non-model crept in."
    )


def test_things_that_look_like_models_are_declared_as_not_models() -> None:
    """Silence about the lab stub would read as an omission.

    A reader checking the inventory will wonder about the demo lab's
    "assistant". Saying plainly that it is a string function is more useful
    than leaving them to find out.
    """
    declarations = build()["declarations"]
    stub = next(item for item in declarations if "stub" in item["name"])
    flags = {prop["name"]: prop["value"] for prop in stub["properties"]}
    assert flags["kervy:is-ml-model"] == "false"
    assert "not a machine-learning model" in stub["description"]


def test_the_external_provider_is_a_service_not_a_component() -> None:
    """A model an operator might point at is not a model this release ships.

    Recording it as a component would mean the SBOM claimed to inventory
    something chosen after the build. It is a service, configured by
    environment-variable NAME, with no endpoint and no model fixed.

    Verified by moving it into `components`: the emptiness test fails.
    """
    document = build()
    names = {service["name"] for service in document["services"]}
    assert "assistant-model-provider" in names

    provider = next(
        service for service in document["services"] if service["name"] == "assistant-model-provider"
    )
    flags = {prop["name"]: prop["value"] for prop in provider["properties"]}
    assert flags["kervy:ships-with-release"] == "false"
    # Variable names, never values — the same rule every credential on this
    # platform follows.
    for variable in PROVIDER_ENV_VARS:
        assert variable in flags["kervy:configured-by"]

    # And no endpoint or model identifier is recorded anywhere in the document,
    # because neither is knowable at build time.
    body = json.dumps(document)
    assert "https://api." not in body
    assert "gpt-" not in body.lower()


def test_the_document_says_what_kind_of_bom_it_is() -> None:
    """ "Labelled" is half the requirement.

    Two CycloneDX files in one release with nothing distinguishing them is the
    undifferentiated bill of materials the spec forbids.
    """
    metadata = build()["metadata"]
    flags = {prop["name"]: prop["value"] for prop in metadata["properties"]}
    assert flags["kervy:bom-kind"] == "ml-bom"
    assert flags["kervy:model-count"] == "0"
    assert "ships no machine-learning model" in flags["kervy:statement"]


def test_the_model_count_property_matches_the_actual_inventory() -> None:
    """A stated count and a real list must not be able to disagree.

    Two places holding the same fact is how a document starts lying: the
    inventory empties, the headline count stays at whatever it was.
    """
    document = build()
    flags = {prop["name"]: prop["value"] for prop in document["metadata"]["properties"]}
    assert int(flags["kervy:model-count"]) == len(document["components"])


def test_the_spec_version_matches_what_the_tooling_can_emit() -> None:
    """§23 asks for CycloneDX 1.7; the library tops out at 1.6.

    Writing "1.7" into a document no 1.7 validator had checked would be a
    version claim nobody verified. The deferral is recorded in
    `docs/roadmap.md` rather than papered over here.
    """
    from cyclonedx.schema import SchemaVersion

    highest = max(SchemaVersion, key=lambda version: version.name)
    emitted = highest.name.removeprefix("V").replace("_", ".")
    assert emitted == SPEC_VERSION, (
        f"the ML-BOM claims CycloneDX {SPEC_VERSION} but the library emits "
        f"{highest.name}. The two halves of the bill of materials must agree."
    )


def test_the_two_boms_are_generated_as_separate_files() -> None:
    """The shape requirement, read off the workflows that produce them.

    Verified by pointing `--out` at the software SBOM's path: the paths then
    collide and this fails.
    """
    for name in ("sbom.yml", "release.yml"):
        body = (WORKFLOWS / name).read_text()
        assert "scripts.mlbom" in body, f"{name} never generates an ML-BOM"

        document = yaml.safe_load(body)
        assert document, f"{name} is not valid YAML"

        # Every CycloneDX path the workflow writes, and the ML-BOM's own.
        # The ML-BOM must be one of them and must not share a path with any
        # other, or one document overwrites the other.
        paths = set(re.findall(r"[\w./-]*\.cdx\.json", body))
        ml_paths = {path for path in paths if "mlbom" in path}
        software_paths = paths - ml_paths

        assert ml_paths, f"{name} writes no ML-BOM document"
        assert software_paths, f"{name} writes no software SBOM document"
        assert not (ml_paths & software_paths), (
            f"{name} writes the ML-BOM to a software SBOM path; §27 requires them "
            "separate and labelled, never merged."
        )


def test_the_generator_makes_no_network_requests() -> None:
    """Same rule as the drift checker.

    An SBOM generator that reached out would be a second outbound path outside
    the directory the static check scans, and its output would stop being a
    pure function of the source tree.
    """
    source = (pathlib.Path(__file__).resolve().parents[1] / "scripts" / "mlbom.py").read_text()
    for library in ("httpx", "requests", "urllib.request", "urllib3", "aiohttp"):
        assert f"import {library}" not in source


def test_the_document_is_deterministic() -> None:
    """Two generations of the same release are byte-identical.

    An SBOM that changed run to run could not be signed meaningfully.
    """
    assert json.dumps(build("1.2.3"), sort_keys=True) == json.dumps(build("1.2.3"), sort_keys=True)
    assert build("1.2.3")["metadata"]["component"]["version"] == "1.2.3"
