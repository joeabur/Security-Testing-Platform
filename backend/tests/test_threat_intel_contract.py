"""Threat-intel correlation: the contract and its only provider
(docs/roadmap.md — design-only this phase, no live feed).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.threat_intel.contract import (
    NullThreatIntelProvider,
    ThreatIntelContext,
    ThreatIntelProvider,
)


async def test_the_null_provider_answers_every_advisory_as_not_assessed() -> None:
    provider: ThreatIntelProvider = NullThreatIntelProvider()

    result = await provider.correlate(("CVE-2024-12345", "GHSA-aaaa-bbbb-cccc"))

    assert set(result) == {"CVE-2024-12345", "GHSA-aaaa-bbbb-cccc"}
    for context in result.values():
        assert context.known_exploited is None
        assert context.epss_score is None
        assert context.source is None
        assert context.retrieved_at is None


async def test_the_null_provider_answers_nothing_for_an_empty_request() -> None:
    provider: ThreatIntelProvider = NullThreatIntelProvider()

    assert await provider.correlate(()) == {}


def test_null_provider_satisfies_the_protocol_at_runtime() -> None:
    assert isinstance(NullThreatIntelProvider(), ThreatIntelProvider)


def test_a_populated_context_requires_a_retrieval_timestamp() -> None:
    with pytest.raises(ValueError, match="retrieved_at"):
        ThreatIntelContext(advisory="CVE-2024-12345", known_exploited=True)

    with pytest.raises(ValueError, match="retrieved_at"):
        ThreatIntelContext(advisory="CVE-2024-12345", epss_score=0.5)


def test_a_fully_unassessed_context_needs_no_timestamp() -> None:
    # The NullThreatIntelProvider's own shape: nothing populated, nothing
    # to timestamp.
    context = ThreatIntelContext(advisory="CVE-2024-12345")
    assert context.retrieved_at is None


def test_epss_score_must_be_a_probability() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="epss_score"):
        ThreatIntelContext(advisory="CVE-2024-12345", epss_score=1.5, retrieved_at=now)
    with pytest.raises(ValueError, match="epss_score"):
        ThreatIntelContext(advisory="CVE-2024-12345", epss_score=-0.1, retrieved_at=now)


def test_a_fully_populated_context_is_accepted() -> None:
    now = datetime.now(UTC)
    context = ThreatIntelContext(
        advisory="CVE-2024-12345",
        known_exploited=True,
        epss_score=0.87,
        source="cisa-kev",
        retrieved_at=now,
    )
    assert context.known_exploited is True
    assert context.epss_score == 0.87
    assert context.source == "cisa-kev"
    assert context.retrieved_at == now
