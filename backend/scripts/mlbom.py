"""Generate the ML-BOM — the machine-learning half of the bill of materials.

`docs/BUILD_SPEC.md` §23 asks for "CycloneDX 1.7 SBOM + ML-BOM for lab models",
and §27's addendum is stricter about the shape: *software SBOM and ML-BOM ship
as separate labelled components of one release artifact, **never merged into one
undifferentiated bill of materials***. So this writes its own document, and
`sbom.yml` publishes it beside the software SBOM rather than folding it in.

## The honest answer is mostly "nothing"

This repository ships **no model**: no weights, no checkpoints, no training
data, no fine-tune. Two things could be mistaken for one, and both are listed
here as what they are rather than as models:

* **The demo lab's "model" is a string function.** `lab/vulnerable_ai_app/model.py`
  is a few hundred lines of deterministic string handling that behaves the way
  a badly-isolated assistant behaves. Listing it as an ML component would be
  inflation of exactly the kind §2.8 forbids ("no unmeasured coverage
  percentages", and no fictional inventory either). It appears as a declaration
  that it is *not* a model.
* **The AI assistant layer calls somebody else's model.** The endpoint, the
  model name and the API key are all operator-supplied at run time, by
  environment-variable *name*. Nothing about which model an operator picks is
  knowable at build time, so it is recorded as an external service with no
  endpoint and no model fixed — which is the true state, and more useful to a
  reader than a guessed entry.

An ML-BOM with zero model components is a real answer to "what models does this
ship?". A generator that invented entries to look complete would make the
document worthless for the one question it exists to answer.

## No network, and deterministic

Same rule as `framework_drift.py`: this makes no requests. It reads the
repository's own configuration surface and emits a document, so its output is a
pure function of the source tree and can be asserted in a test.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

#: The CycloneDX schema version emitted. §23 asks for 1.7; `cyclonedx-python-lib`
#: tops out at 1.6 today and the software SBOM is generated at 1.6 too, so the
#: two halves match. Writing "1.7" into a document that no 1.7 validator had
#: checked would be a version claim nobody verified — see `docs/releasing.md`.
SPEC_VERSION = "1.6"

BOM_FORMAT = "CycloneDX"

#: Environment variables that select the assistant's model at run time. Names
#: only — this file never reads their values, and the ML-BOM records which
#: knobs exist rather than how one deployment set them.
PROVIDER_ENV_VARS = ("KERVY_AI_PROVIDER", "KERVY_AI_ENDPOINT", "KERVY_AI_MODEL")


def _declarations() -> list[dict[str, Any]]:
    """Things a reader might expect to be models, stated as what they are."""
    return [
        {
            "name": "demo-lab-assistant-stub",
            "type": "application",
            "description": (
                "The demo lab's assistant is deterministic string handling "
                "(demo-target/lab/vulnerable_ai_app/model.py), not a machine-learning "
                "model. It has no weights, no training data and no inference "
                "dependency. It is listed here so its absence from the model "
                "inventory is a statement rather than an omission."
            ),
            "properties": [
                {"name": "kervy:is-ml-model", "value": "false"},
                {"name": "kervy:reason", "value": "deterministic string stub"},
            ],
        }
    ]


def _external_model_services() -> list[dict[str, Any]]:
    """The models this platform can be pointed at, none of them shipped."""
    return [
        {
            "name": "assistant-model-provider",
            "description": (
                "The AI assistant layer calls an OpenAI-compatible endpoint chosen by "
                "the operator at run time. The endpoint, the model identifier and the "
                "credential are all supplied by environment variable, so no specific "
                "model is part of this release."
            ),
            "authenticated": True,
            "x-trust-boundary": True,
            "data": [
                {
                    "flow": "bi-directional",
                    "classification": (
                        "Finding text and fenced evidence excerpts out; drafted prose "
                        "back. Evidence is fenced as data before it reaches a model."
                    ),
                }
            ],
            "properties": [
                {"name": "kervy:configured-by", "value": ", ".join(PROVIDER_ENV_VARS)},
                {"name": "kervy:ships-with-release", "value": "false"},
                {"name": "kervy:optional", "value": "true"},
                {
                    "name": "kervy:absent-behaviour",
                    "value": (
                        "With no provider configured the assistant layer is absent and "
                        "the platform runs unchanged."
                    ),
                },
            ],
        },
        {
            "name": "deterministic-fake-provider",
            "description": (
                "The provider used by the test suite (app/core/assistant/fake.py). "
                "Deterministic, local, and not a model: it exists so no test run "
                "consumes paid API tokens."
            ),
            "authenticated": False,
            "x-trust-boundary": False,
            "properties": [
                {"name": "kervy:is-ml-model", "value": "false"},
                {"name": "kervy:used-in", "value": "tests and CI only"},
            ],
        },
    ]


def build(version: str = "0.1.0") -> dict[str, Any]:
    """The ML-BOM document.

    `components` is the model inventory and is deliberately empty. Everything
    that might be mistaken for a model is in `declarations`, and everything the
    platform can be pointed at is in `services`.
    """
    return {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "kervy-security",
                "version": version,
                "description": "Machine-learning bill of materials.",
            },
            "properties": [
                {"name": "kervy:bom-kind", "value": "ml-bom"},
                {
                    "name": "kervy:model-count",
                    "value": "0",
                },
                {
                    "name": "kervy:statement",
                    "value": (
                        "This release ships no machine-learning model: no weights, no "
                        "checkpoints, no training data, no fine-tune. The assistant "
                        "layer calls an operator-supplied endpoint; the demo lab uses "
                        "a deterministic string stub."
                    ),
                },
            ],
        },
        # The model inventory. Empty, and that is the finding.
        "components": [],
        "services": _external_model_services(),
        "declarations": _declarations(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", help="write the ML-BOM here instead of stdout")
    parser.add_argument("--version", default="0.1.0", help="release version to record")
    args = parser.parse_args(argv)

    document = json.dumps(build(args.version), indent=2, sort_keys=True) + "\n"
    if args.out:
        pathlib.Path(args.out).write_text(document)
    else:
        sys.stdout.write(document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
