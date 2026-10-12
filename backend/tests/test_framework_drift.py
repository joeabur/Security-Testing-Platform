"""The weekly framework-drift check (docs/BUILD_SPEC.md §23).

A stale framework pin is a quiet correctness problem: "OWASP LLM01" names
different things in different editions, so a report mapped against a version
upstream has moved past is confidently wrong. The check exists to notice.

These tests concentrate on the one way a drift check fails worst — reporting
"no drift" when it simply did not look. A lookup that returned nothing must
never land in the same bucket as a lookup that returned a matching version.
"""

from __future__ import annotations

from datetime import date

from app.core.findings.frameworks import FRAMEWORKS, FrameworkVersion
from scripts.framework_drift import (
    MANUAL_REVIEW_DAYS,
    checkable,
    compare,
)

TODAY = date(2026, 9, 20)

TABLE = {
    "repo_backed": FrameworkVersion(
        version="v2026.09", retrieved="2026-09-17", source="github.com/mitre-atlas/atlas-data"
    ),
    "page_backed_fresh": FrameworkVersion(
        version="2023", retrieved="2026-09-17", source="owasp.org/API-Security/editions/2023/"
    ),
    "page_backed_stale": FrameworkVersion(
        version="AI 100-1 (2023)", retrieved="2024-01-01", source="nist.gov/itl/ai-rmf"
    ),
    # Hosted on github.com, like `repo_backed`, but explicitly excluded from
    # mechanical checking (`_NOT_MECHANICALLY_CHECKABLE`) because its
    # upstream repository publishes no tags or releases — ships editions as
    # branches instead. Must fall through to the by-date manual-review path
    # like a page-backed framework, not sit forever in "could not be read".
    "owasp_llm_2026": FrameworkVersion(
        version="2026 edition",
        retrieved="2026-09-17",
        source="github.com/GenAI-Security-Project/GenAI-LLM-Top10",
    ),
}


def test_only_repository_backed_frameworks_are_checked_mechanically() -> None:
    keys = {item.key for item in checkable(TABLE)}
    assert keys == {"repo_backed"}


def test_a_github_hosted_framework_with_no_tags_is_not_mechanically_checkable() -> None:
    """`owasp_llm_2026`'s repository hosts the edition but ships it as
    branches, never a tag or a release — `checkable()` would otherwise
    treat any `github.com` source as tag-comparable and report this one
    "could not be read" every single week, forever."""
    report = compare({}, frameworks=TABLE, today=TODAY)
    assert "owasp_llm_2026" not in report.unknown
    assert "owasp_llm_2026" in report.current


def test_a_matching_upstream_version_is_current() -> None:
    report = compare({"repo_backed": "v2026.09"}, frameworks=TABLE, today=TODAY)
    assert report.drifted == {}
    assert "repo_backed" in report.current


def test_a_moved_upstream_version_is_drift() -> None:
    report = compare({"repo_backed": "v2026.12"}, frameworks=TABLE, today=TODAY)
    assert report.drifted == {"repo_backed": ("v2026.09", "v2026.12")}
    assert report.needs_attention
    assert "Upstream has moved" in report.as_markdown()


def test_a_non_version_tag_name_is_unknown_not_drift() -> None:
    """`OWASP/ASVS`'s GitHub "latest" release is tagged literally `latest`,
    not a version — confirmed live via `git ls-remote --tags`. Trusting
    that string would report every pinned repo-backed framework as
    "drifted to latest" the moment its own `latest` tag was anything but
    a real version. A string with no digit in it cannot be a version, so
    it must land in `unknown` ("a gap in this check"), never `drifted`
    ("upstream has moved") — the workflow's own fetch step is fixed
    separately to prefer a real version-shaped tag, but this is the
    second, independently testable line of defense."""
    report = compare({"repo_backed": "latest"}, frameworks=TABLE, today=TODAY)
    assert report.drifted == {}
    assert "repo_backed" in report.unknown
    assert "latest" in report.unknown["repo_backed"]


def test_a_failed_lookup_is_never_reported_as_current() -> None:
    """The failure this whole check exists to avoid.

    If a missing upstream version fell through to "current", a GitHub API
    outage or a renamed repository would make the weekly job report that every
    pin is fine — which is worse than not running it, because somebody would
    believe it.

    Verified by making `compare` treat a missing lookup as current: this fails.
    """
    report = compare({}, frameworks=TABLE, today=TODAY)
    assert "repo_backed" in report.unknown
    assert "repo_backed" not in report.current
    assert "repo_backed" not in report.drifted
    assert report.needs_attention
    assert "Could not be read" in report.as_markdown()
    assert "not a clean result" in report.as_markdown()


def test_a_page_backed_framework_is_reviewed_by_date_not_by_lookup() -> None:
    """Nothing read these, so nothing may say they are current forever.

    A framework published as a web page has no tag to compare. Reporting it as
    current would be reporting that the script did not look at it.
    """
    report = compare({"repo_backed": "v2026.09"}, frameworks=TABLE, today=TODAY)
    assert report.review_due == {"page_backed_stale": "2024-01-01"}
    assert "page_backed_fresh" in report.current
    assert "Manual review due" in report.as_markdown()


def test_the_review_window_is_what_decides() -> None:
    fresh = compare({"repo_backed": "v2026.09"}, frameworks=TABLE, today=date(2024, 6, 1))
    assert fresh.review_due == {}

    later = date(2024, 1, 1) + __import__("datetime").timedelta(days=MANUAL_REVIEW_DAYS + 1)
    stale = compare({"repo_backed": "v2026.09"}, frameworks=TABLE, today=later)
    assert "page_backed_stale" in stale.review_due


def test_version_spellings_that_mean_the_same_release_do_not_drift() -> None:
    """`ATLAS v2026.09` and `v2026.09` are one release.

    Loose on purpose, and the asymmetry is deliberate: a false "no drift"
    leaves a stale mapping in the product, a false drift costs a maintainer
    one closed issue. The comparison errs towards reporting.
    """
    for spelling in ("v2026.09", "2026.09", "ATLAS v2026.09"):
        report = compare({"repo_backed": spelling}, frameworks=TABLE, today=TODAY)
        assert report.drifted == {}, spelling


def test_a_clean_report_says_so_and_exits_zero_shaped() -> None:
    table = {"repo_backed": TABLE["repo_backed"]}
    report = compare({"repo_backed": "v2026.09"}, frameworks=table, today=TODAY)
    assert not report.needs_attention
    assert "Every pinned framework edition is current" in report.as_markdown()


def test_the_real_table_is_checkable_and_every_entry_is_accounted_for() -> None:
    """Run against the frameworks actually shipped, not only the fixture.

    Every key in `FRAMEWORKS` must land in exactly one bucket. A key that fell
    through all four would be a framework nothing ever reviews.
    """
    report = compare({}, today=TODAY)
    buckets = (
        set(report.drifted) | set(report.review_due) | set(report.unknown) | set(report.current)
    )
    assert buckets == set(FRAMEWORKS)
