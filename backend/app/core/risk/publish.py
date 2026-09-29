"""Render the risk model's tables as Markdown.

§12 requires every input to have "a published numeric table in
`docs/risk-model.md` and the report appendix". Generating both from the same
constants the scorer uses means the published numbers cannot drift from the
ones actually applied — a documentation file maintained by hand would be
wrong the first time a weight changed.
"""

from app.core.risk.model import (
    CONFIDENCE_WEIGHTS,
    ENVIRONMENT_MODIFIERS,
    EXPOSURE_MODIFIERS,
    IMPACT_VALUES,
    RISK_MODEL_VERSION,
    SEVERITY_BANDS,
)


def _table(title: str, header: str, rows: list[tuple[str, str]]) -> str:
    lines = [f"### {title}", "", f"| {header} | Value |", "|---|---|"]
    lines += [f"| `{name}` | {value} |" for name, value in rows]
    return "\n".join(lines) + "\n"


def render_markdown() -> str:
    bands = []
    previous: float | None = None
    for threshold, severity in SEVERITY_BANDS:
        upper = "10.0" if previous is None else f"< {previous}"
        bands.append((severity.value, f">= {threshold} and {upper}"))
        previous = threshold

    return "\n".join(
        [
            "# Risk model",
            "",
            "<!-- Generated from app/core/risk/model.py by app/core/risk/publish.py.",
            "     Do not edit by hand: a table maintained separately from the scorer",
            "     is wrong the first time a weight changes. -->",
            "",
            f"**Model version:** `{RISK_MODEL_VERSION}`",
            "",
            "```",
            "risk = impact × likelihood × confidence_weight × exposure_modifier",
            "```",
            "",
            "`exposure_modifier` is the exposure value multiplied by the environment",
            "value: what changes between environments is who can reach the finding",
            "today, not what it would cost if they did.",
            "",
            "`likelihood` is the **lower bound** of the measured attack success rate's",
            "95% confidence interval for a probabilistic finding, 1.0 for one",
            "reproduced on every attempt, and an estimate for a design-review finding.",
            "Using the point estimate instead would treat sampling noise as an",
            "established fact.",
            "",
            _table("Impact", "Ordinal", [(k.value, str(v)) for k, v in IMPACT_VALUES.items()]),
            _table(
                "Confidence weight",
                "Confidence",
                [(k.value, str(v)) for k, v in CONFIDENCE_WEIGHTS.items()],
            ),
            _table(
                "Exposure",
                "Reachability",
                [(k.value, str(v)) for k, v in EXPOSURE_MODIFIERS.items()],
            ),
            _table(
                "Environment",
                "Environment",
                [(k.value, str(v)) for k, v in ENVIRONMENT_MODIFIERS.items()],
            ),
            _table("Severity banding", "Severity", bands),
            "## Three scoring systems, never blended",
            "",
            "1. **Kervy risk score** — always present, the model above.",
            "2. **CVSS 4.0** — only for findings that genuinely fit CVSS. A vector is",
            '   never manufactured for something like "the model followed an injected',
            '   instruction", which CVSS has no way to express.',
            "3. **AIVSS v0.8** — optional, off by default, labelled as draft",
            "   methodology subject to change before v1.0.",
            "",
            "They appear in separate fields and are never averaged together.",
            "",
        ]
    )
