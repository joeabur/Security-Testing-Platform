"""Detect drift between the pinned framework editions and upstream.

`docs/BUILD_SPEC.md` §23 asks for a weekly upstream framework version check
that opens an issue on drift, and §27 requires every mapping to be traceable to
a pinned version with a retrieval date. Together those mean: a pinned edition
that upstream has moved past is a silent correctness problem, because
"OWASP LLM01" names different things in different editions and a report that
does not notice is confidently wrong.

**This module makes no network requests, deliberately.** Every outbound request
in the application goes through `GatedTransport`, and a maintenance script that
opened its own connection would be a second HTTP path — the exact thing the
static check in `tests/security/` exists to prevent, weakened by putting it
just outside the directory that check scans. So the fetching happens in the
workflow, where it is visible in the job log, and this module does the part
worth testing: comparing what was fetched against what is pinned, and deciding
what that means.

It is also why `compare()` is pure. A drift report that could only be produced
by hitting the network could only be tested by hitting the network.

## Two kinds of entry, and only one can be checked automatically

Some framework editions live in a git repository with tags. Those can be
compared mechanically. Others are a published web page with no machine-readable
version — OWASP API Security's edition pages, the NIST AI RMF — and for those
a script that reported "no drift" would be reporting that it did not look.
`ReviewDue` is what it reports instead, driven by the retrieval date.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from app.core.findings.frameworks import FRAMEWORKS, FrameworkVersion

#: How long a manually-checked framework may go unreviewed before this reports
#: it. A year: these documents are revised on roughly annual cycles, and a
#: shorter window would produce an issue nobody reads.
MANUAL_REVIEW_DAYS = 365

#: `owner/repo` out of a source string. Only github.com sources are
#: mechanically checkable; everything else is a page somebody has to read.
_GITHUB = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")

#: Hosted on github.com but not actually checkable there — a `github.com`
#: source means "has tags/releases to compare" for `owasp_asvs`,
#: `mitre_atlas` and `mitre_attack`, but `GenAI-Security-Project/GenAI-LLM-Top10`
#: (`owasp_llm_2026`) ships its editions as long-lived branches
#: (`release-candidate-1`, `update/LLM03-supply-chain-2026-refresh`, ...),
#: never a git tag or a GitHub Release (confirmed live: `git ls-remote --tags`
#: against it returns nothing). Treating it as mechanically checkable made
#: this check report "could not be read" every single week forever — a
#: permanent gap dressed up as a transient one. Keyed here instead, so it
#: falls through to the same by-date manual-review path `owasp_asi_2026`,
#: `owasp_api_2023`, `nist_ai_rmf` and `nist_ssdf` already use.
_NOT_MECHANICALLY_CHECKABLE: frozenset[str] = frozenset({"owasp_llm_2026"})


@dataclass(frozen=True)
class Checkable:
    """A framework whose upstream version can be read from a git repository."""

    key: str
    owner: str
    repo: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass
class DriftReport:
    """What changed upstream, what needs a human, and what could not be read."""

    #: key -> (pinned, upstream). Upstream has moved.
    drifted: dict[str, tuple[str, str]] = field(default_factory=dict)
    #: Frameworks with no machine-readable version whose retrieval date is old.
    review_due: dict[str, str] = field(default_factory=dict)
    #: Checkable frameworks the fetch step did not return a version for. Not
    #: the same as "no drift": a failed lookup is a gap, and saying so is the
    #: whole point of separating this from `drifted`.
    unknown: dict[str, str] = field(default_factory=dict)
    #: Checked and current.
    current: dict[str, str] = field(default_factory=dict)

    @property
    def needs_attention(self) -> bool:
        return bool(self.drifted or self.review_due or self.unknown)

    def as_markdown(self) -> str:
        lines = ["## Framework version drift", ""]
        if not self.needs_attention:
            lines += ["Every pinned framework edition is current, and no manual review is due.", ""]
        if self.drifted:
            lines += [
                "### Upstream has moved",
                "",
                "| Framework | Pinned | Upstream |",
                "|---|---|---|",
            ]
            for key, (pinned, upstream) in sorted(self.drifted.items()):
                lines.append(f"| `{key}` | {pinned} | {upstream} |")
            lines += [
                "",
                "Update `backend/app/core/findings/frameworks.py` **and the mappings "
                "themselves**. Bumping the version string without re-reading the edition "
                "would make every finding claim a mapping it does not have.",
                "",
            ]
        if self.review_due:
            lines += [
                "### Manual review due",
                "",
                "These have no machine-readable version, so nothing here checked them. "
                f"Each was last read more than {MANUAL_REVIEW_DAYS} days ago.",
                "",
                "| Framework | Last retrieved |",
                "|---|---|",
            ]
            for key, retrieved in sorted(self.review_due.items()):
                lines.append(f"| `{key}` | {retrieved} |")
            lines.append("")
        if self.unknown:
            lines += [
                "### Could not be read",
                "",
                "The upstream lookup returned nothing for these. That is a gap in this "
                "check, not a clean result.",
                "",
            ]
            for key, reason in sorted(self.unknown.items()):
                lines.append(f"- `{key}`: {reason}")
            lines.append("")
        if self.current:
            lines += ["<details><summary>Current</summary>", ""]
            for key, version in sorted(self.current.items()):
                lines.append(f"- `{key}`: {version}")
            lines += ["", "</details>", ""]
        return "\n".join(lines)


def checkable(frameworks: Mapping[str, FrameworkVersion] | None = None) -> list[Checkable]:
    """The frameworks whose upstream version lives in a git repository."""
    table = frameworks if frameworks is not None else FRAMEWORKS
    found: list[Checkable] = []
    for key, entry in table.items():
        if key in _NOT_MECHANICALLY_CHECKABLE:
            continue
        match = _GITHUB.search(entry.source)
        if match:
            found.append(
                Checkable(key=key, owner=match.group(1), repo=match.group(2).removesuffix(".git"))
            )
    return found


def _version_core(version: str) -> str:
    """The numeric part of a version string, with the decoration removed.

    `v2026.09`, `2026.09` and `ATLAS v2026.09` are one release, and a
    comparison that treated them as three would file an issue every week. So
    the longest dotted-numeric run is what is compared, and anything else falls
    back to the stripped string.

    It stays deliberately literal about digits: `2026.09` and `2026.9` compare
    as different. That errs towards reporting, which is the right direction —
    a false "no drift" leaves a stale mapping in the product, a false drift
    costs a maintainer one closed issue.
    """
    numbers = re.findall(r"\d+(?:\.\d+)*", version)
    if numbers:
        return str(max(numbers, key=len))
    return re.sub(r"[^0-9a-z]", "", version.strip().lower())


def compare(
    observed: Mapping[str, str],
    *,
    frameworks: Mapping[str, FrameworkVersion] | None = None,
    today: date | None = None,
) -> DriftReport:
    """Compare pinned editions against what the workflow read upstream.

    `observed` maps a framework key to the latest upstream tag or release name.
    A key that is absent is reported as `unknown`, never as current — silence
    from a lookup is not a result.
    """
    table = dict(frameworks if frameworks is not None else FRAMEWORKS)
    moment = today or date.today()
    report = DriftReport()
    mechanical = {item.key for item in checkable(table)}

    for key, entry in table.items():
        if key not in mechanical:
            try:
                retrieved = datetime.strptime(entry.retrieved, "%Y-%m-%d").date()
            except ValueError:
                report.unknown[key] = f"unparseable retrieval date {entry.retrieved!r}"
                continue
            if moment - retrieved > timedelta(days=MANUAL_REVIEW_DAYS):
                report.review_due[key] = entry.retrieved
            else:
                report.current[key] = f"{entry.version} (manual, read {entry.retrieved})"
            continue

        upstream = observed.get(key)
        if not upstream:
            report.unknown[key] = "upstream lookup returned no version"
        elif not re.search(r"\d", upstream):
            # A real version string always has a digit in it somewhere.
            # `OWASP/ASVS`'s GitHub "latest" release is tagged literally
            # `latest`, not a version — trusting that literally would
            # report every pinned edition as "drifted to latest" forever.
            # The workflow's own fetch step now prefers a version-shaped
            # tag over this, but this is kept as a second, independently
            # testable line of defense against the same footgun recurring
            # for some other repository later.
            report.unknown[key] = f"upstream returned a non-version tag name: {upstream!r}"
        elif _version_core(upstream) == _version_core(entry.version):
            report.current[key] = entry.version
        else:
            report.drifted[key] = (entry.version, upstream)

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--observed",
        help="JSON file mapping framework key -> upstream version. '-' reads stdin.",
    )
    parser.add_argument("--out", help="write the markdown report here as well as to stdout")
    parser.add_argument(
        "--list-sources",
        action="store_true",
        help="print the checkable repositories as JSON and exit",
    )
    args = parser.parse_args(argv)

    if args.list_sources:
        print(
            json.dumps(
                [{"key": item.key, "repo": item.slug} for item in checkable()],
                indent=2,
            )
        )
        return 0

    observed: dict[str, str] = {}
    if args.observed:
        raw = sys.stdin.read() if args.observed == "-" else pathlib.Path(args.observed).read_text()
        loaded = json.loads(raw or "{}")
        if isinstance(loaded, dict):
            observed = {str(k): str(v) for k, v in loaded.items() if v}

    report = compare(observed)
    markdown = report.as_markdown()
    print(markdown)
    if args.out:
        pathlib.Path(args.out).write_text(markdown)
    # 1 means "a human should look", not "this script broke". The workflow
    # opens an issue on 1 rather than failing the run.
    return 1 if report.needs_attention else 0


if __name__ == "__main__":
    raise SystemExit(main())
