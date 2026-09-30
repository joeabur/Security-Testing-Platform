"""Pinned framework versions, with the date each was retrieved.

`docs/BUILD_SPEC.md` §27 requires every framework mapping to be traceable to a
pinned upstream version with a retrieval date. A mapping without one is not
verifiable: "OWASP LLM01" means different things in different editions, and
MITRE ATLAS renames and retires technique IDs between calendar releases.

So a finding carries not only `mappings` but `mapping_versions`, and the values
come from here rather than from whatever the probe happened to say. One table,
one place to update, and a report that states what it was mapped against.

**Only frameworks this platform actually emits mappings for appear here.** A
mapping key with no entry is reported without a version rather than given a
plausible-looking one — an invented version is the same class of error as an
invented CVE.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class FrameworkVersion:
    """A pinned edition of one framework."""

    #: The edition as its publisher names it.
    version: str
    #: ISO date this edition's content was read into the mappings below.
    retrieved: str
    source: str

    def as_string(self) -> str:
        """The form stored on a finding and rendered in a report."""
        return f"{self.version} (retrieved {self.retrieved})"


#: Keys match `group_mappings` in `normalize.py`. `cwe` is deliberately absent:
#: CWE identifiers are stable across MITRE's releases in a way the others are
#: not, and pinning a CWE "version" would imply a precision that does not exist.
FRAMEWORKS: Mapping[str, FrameworkVersion] = MappingProxyType(
    {
        "owasp_llm_2026": FrameworkVersion(
            version="2026 edition",
            retrieved="2026-09-17",
            source="github.com/GenAI-Security-Project/GenAI-LLM-Top10, 2026/final/",
        ),
        "owasp_asi_2026": FrameworkVersion(
            version="2026 (ASI01-ASI10)",
            retrieved="2026-09-17",
            source="genai.owasp.org",
        ),
        "owasp_api_2023": FrameworkVersion(
            version="2023",
            retrieved="2026-09-17",
            source="owasp.org/API-Security/editions/2023/en/0x00-header/",
        ),
        "owasp_asvs": FrameworkVersion(
            version="5.0.0",
            retrieved="2026-09-30",
            source="github.com/OWASP/ASVS",
        ),
        "mitre_atlas": FrameworkVersion(
            version="v2026.09",
            retrieved="2026-09-17",
            source="github.com/mitre-atlas/atlas-data",
        ),
        "nist_ai_rmf": FrameworkVersion(
            version="AI 100-1 (2023)",
            retrieved="2026-09-17",
            source="nist.gov/itl/ai-risk-management-framework",
        ),
        "nist_ssdf": FrameworkVersion(
            version="SP 800-218 v1.1",
            retrieved="2026-09-17",
            source="csrc.nist.gov/pubs/sp/800/218/final",
        ),
    }
)


def versions_for(mappings: Mapping[str, list[str]]) -> dict[str, str]:
    """The pinned version of each framework this finding actually maps to.

    Only keys present in `mappings` are reported, so a finding does not claim
    to have been assessed against a framework it carries no reference for.
    """
    return {
        key: FRAMEWORKS[key].as_string() for key in mappings if key in FRAMEWORKS and mappings[key]
    }
