"""AWS: read-only S3 public-exposure inventory (Pentest module Phase 4).

Every call here is read-only by construction — `list_buckets`,
`get_bucket_location`, `get_bucket_policy_status`, `get_bucket_acl` — never
a `put_*`/`delete_*`/`create_*` verb. Enforced by this module's own test, a
static grep for a forbidden-verb-prefix method call, the same "no write
verbs" discipline `app/core/vcs`'s pull-request layer already applies to
its own API surface (`docs/security-model.md` guarantee #20).

`boto3` is a synchronous library, so every call is wrapped in
`asyncio.to_thread` rather than blocking the event loop — the same pattern
`app/core/domain/tls_probe.py` uses for a raw-socket TLS handshake.

The credential a `credential_env_var` resolves to is a JSON object
(`{"access_key_id": ..., "secret_access_key": ..., "session_token": ...}`,
the last optional) rather than a bare string, because S3 access needs a
key pair, not one token — the same reason `SyntheticAccount` only needed a
single string for a bearer header and this does not.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from app.core.cloud.contract import BucketExposure, CloudProviderError, CloudTarget


def _credential_pair(target: CloudTarget, credential: str) -> tuple[str, str, str | None]:
    try:
        parsed = json.loads(credential)
    except json.JSONDecodeError as exc:
        raise CloudProviderError(
            f"credential for {target.credential_env_var!r} is not valid JSON; expected "
            '{"access_key_id": ..., "secret_access_key": ...}'
        ) from exc
    if not isinstance(parsed, dict):
        raise CloudProviderError(
            f"credential for {target.credential_env_var!r} must be a JSON object"
        )
    access_key_id = parsed.get("access_key_id")
    secret_access_key = parsed.get("secret_access_key")
    if not access_key_id or not secret_access_key:
        raise CloudProviderError(
            f"credential for {target.credential_env_var!r} must include "
            "access_key_id and secret_access_key"
        )
    return access_key_id, secret_access_key, parsed.get("session_token")


def _client(target: CloudTarget, credential: str) -> Any:
    try:
        import boto3
    except ImportError as exc:
        raise CloudProviderError(
            "boto3 is not installed on this worker — install the platform's "
            "'cloud' extra to enable the AWS provider"
        ) from exc

    access_key_id, secret_access_key, session_token = _credential_pair(target, credential)
    return boto3.client(
        "s3",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
        region_name=target.allowed_regions[0] if target.allowed_regions else None,
    )


def _public_status(client: Any, name: str, botocore_exceptions: Any) -> tuple[bool, str]:
    try:
        status = client.get_bucket_policy_status(Bucket=name)
        if status.get("PolicyStatus", {}).get("IsPublic"):
            return True, "bucket policy grants public access (GetBucketPolicyStatus.IsPublic)"
    except botocore_exceptions.ClientError:
        # No bucket policy, or the account cannot read one — the ACL check
        # below is still meaningful either way.
        pass

    try:
        acl = client.get_bucket_acl(Bucket=name)
        for grant in acl.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                group = uri.rsplit("/", 1)[-1]
                return True, f"bucket ACL grants {grant.get('Permission')} to {group}"
    except botocore_exceptions.ClientError:
        pass

    return False, "no public grant found in the bucket policy or ACL"


def _list_exposed_storage_sync(target: CloudTarget, credential: str) -> list[BucketExposure]:
    try:
        import botocore.exceptions
    except ImportError as exc:
        raise CloudProviderError(
            "boto3 is not installed on this worker — install the platform's "
            "'cloud' extra to enable the AWS provider"
        ) from exc

    client = _client(target, credential)
    try:
        response = client.list_buckets()
    except botocore.exceptions.NoCredentialsError as exc:
        raise CloudProviderError(f"AWS credentials were rejected: {exc}") from exc
    except botocore.exceptions.ClientError as exc:
        raise CloudProviderError(f"AWS S3 ListBuckets failed: {exc}") from exc

    results: list[BucketExposure] = []
    for bucket in response.get("Buckets", []):
        name = bucket["Name"]
        try:
            location = client.get_bucket_location(Bucket=name).get("LocationConstraint")
            region = location or "us-east-1"
        except botocore.exceptions.ClientError:
            region = None

        # An out-of-scope bucket is skipped entirely, not merely unprobed —
        # the same "discovery never expands what gets tested" rule
        # `DomainEngine` applies to a subdomain outside `allowed_subdomain_
        # patterns`. An empty `allowed_regions` means no restriction, the
        # schema's own permissive default (`resolve_cloud_scope` does not
        # require it non-empty the way it requires `read_only`).
        if target.allowed_regions and region not in target.allowed_regions:
            continue

        is_public, reason = _public_status(client, name, botocore.exceptions)
        results.append(
            BucketExposure(name=name, region=region, is_public=is_public, public_reason=reason)
        )
    return results


async def list_exposed_storage(target: CloudTarget, credential: str) -> list[BucketExposure]:
    return await asyncio.to_thread(_list_exposed_storage_sync, target, credential)
