"""What a cloud assessment is, and what one provider call reports.

Mirrors `app/core/container/contract.py`'s shape: the engine's input is a
frozen dataclass resolved once from `RulesOfEngagementRecord.asset_scope`
(`resolve_cloud_scope`), never re-read from the RoE mid-run. `read_only` is
not carried here at all — `resolve_cloud_scope` already refuses anything
else at resolve time, so by the time a `CloudTarget` exists, read-only is
not a runtime choice a provider module could get wrong.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CloudTarget:
    provider: str  # "aws" | "azure" | "gcp" — validated by resolve_cloud_scope
    account_ref: str
    credential_env_var: str
    allowed_regions: tuple[str, ...] = ()


@dataclass(frozen=True)
class BucketExposure:
    """One object-storage bucket/container a provider call inventoried."""

    name: str
    region: str | None
    is_public: bool
    #: A human-readable account of *why* — the specific policy/ACL grant, or
    #: "no public grant found" — never just a bare boolean, so a finding's
    #: evidence field has something concrete to show.
    public_reason: str


class CloudProviderError(RuntimeError):
    """The credential is missing/malformed, the SDK is unavailable, or the
    provider call itself failed (auth rejected, account unreachable, ...)."""
