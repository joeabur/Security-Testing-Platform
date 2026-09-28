"""The AWS provider's own logic: credential parsing, public-grant detection,
and the ListBuckets/region-filter control flow (pentest module Phase 4) —
exercised against `boto3`/`botocore`, which are already installed in this
environment, by monkeypatching `_client` (or `boto3.client`) to a fake S3
client rather than reaching a real AWS account. Mirrors
`test_container_pull.py`'s shape for the analogous SDK-boundary checks in
`app/core/container/pull.py`.
"""

from __future__ import annotations

import inspect
import json
import re
import sys
from typing import Any

import botocore.exceptions
import pytest

from app.core.cloud.contract import CloudProviderError, CloudTarget
from app.core.cloud.providers import aws as aws_module
from app.core.cloud.providers.aws import (
    _credential_pair,
    _list_exposed_storage_sync,
    _public_status,
    list_exposed_storage,
)

CREDENTIAL = json.dumps({"access_key_id": "AKIAEXAMPLE", "secret_access_key": "s3cr3t"})

TARGET = CloudTarget(
    provider="aws",
    account_ref="123456789012",
    credential_env_var="AWS_CRED",
)


def _client_error(
    code: str = "AccessDenied", message: str = "nope"
) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError({"Error": {"Code": code, "Message": message}}, "Op")


# --- _credential_pair ---------------------------------------------------------


def test_a_full_credential_is_parsed() -> None:
    credential = json.dumps(
        {"access_key_id": "AKIA1", "secret_access_key": "secret1", "session_token": "tok1"}
    )
    access_key_id, secret_access_key, session_token = _credential_pair(TARGET, credential)
    assert (access_key_id, secret_access_key, session_token) == ("AKIA1", "secret1", "tok1")


def test_a_credential_without_a_session_token_is_parsed() -> None:
    access_key_id, secret_access_key, session_token = _credential_pair(TARGET, CREDENTIAL)
    assert (access_key_id, secret_access_key) == ("AKIAEXAMPLE", "s3cr3t")
    assert session_token is None


def test_non_json_credential_is_refused() -> None:
    with pytest.raises(CloudProviderError, match="not valid JSON"):
        _credential_pair(TARGET, "not-json-at-all")


def test_a_json_array_credential_is_refused() -> None:
    with pytest.raises(CloudProviderError, match="must be a JSON object"):
        _credential_pair(TARGET, "[1, 2, 3]")


@pytest.mark.parametrize(
    "credential",
    [
        json.dumps({"secret_access_key": "s3cr3t"}),
        json.dumps({"access_key_id": "AKIAEXAMPLE"}),
        json.dumps({}),
    ],
)
def test_a_credential_missing_a_required_field_is_refused(credential: str) -> None:
    with pytest.raises(CloudProviderError, match="must include"):
        _credential_pair(TARGET, credential)


# --- _public_status ------------------------------------------------------------


class _FakeClient:
    def __init__(
        self,
        *,
        policy_is_public: bool | None = False,
        policy_raises: bool = False,
        acl_grants: list[dict[str, Any]] | None = None,
        acl_raises: bool = False,
    ) -> None:
        self.policy_is_public = policy_is_public
        self.policy_raises = policy_raises
        self.acl_grants = acl_grants or []
        self.acl_raises = acl_raises

    def get_bucket_policy_status(self, Bucket: str) -> dict[str, Any]:  # noqa: N803
        if self.policy_raises:
            raise _client_error()
        return {"PolicyStatus": {"IsPublic": self.policy_is_public}}

    def get_bucket_acl(self, Bucket: str) -> dict[str, Any]:  # noqa: N803
        if self.acl_raises:
            raise _client_error()
        return {"Grants": self.acl_grants}


def test_a_public_bucket_policy_is_detected() -> None:
    client = _FakeClient(policy_is_public=True)
    is_public, reason = _public_status(client, "my-bucket", botocore.exceptions)
    assert is_public is True
    assert "GetBucketPolicyStatus" in reason


def test_a_public_acl_grant_to_all_users_is_detected_when_no_policy_exists() -> None:
    client = _FakeClient(
        policy_raises=True,
        acl_grants=[
            {
                "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ",
            }
        ],
    )
    is_public, reason = _public_status(client, "my-bucket", botocore.exceptions)
    assert is_public is True
    assert "AllUsers" in reason
    assert "READ" in reason


def test_a_public_acl_grant_to_authenticated_users_is_detected() -> None:
    client = _FakeClient(
        policy_is_public=False,
        acl_grants=[
            {
                "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"},
                "Permission": "WRITE",
            }
        ],
    )
    is_public, reason = _public_status(client, "my-bucket", botocore.exceptions)
    assert is_public is True
    assert "AuthenticatedUsers" in reason


def test_a_private_bucket_with_no_grants_is_not_public() -> None:
    client = _FakeClient(policy_is_public=False, acl_grants=[])
    is_public, reason = _public_status(client, "my-bucket", botocore.exceptions)
    assert is_public is False
    assert "no public grant" in reason


def test_both_policy_and_acl_unreadable_is_not_public() -> None:
    """An account that cannot read either surface gets a conservative,
    non-public verdict — it never fabricates a finding from a denial."""
    client = _FakeClient(policy_raises=True, acl_raises=True)
    is_public, reason = _public_status(client, "my-bucket", botocore.exceptions)
    assert is_public is False
    assert "no public grant" in reason


# --- list_exposed_storage / _list_exposed_storage_sync -------------------------


class _FakeListingClient:
    def __init__(self, buckets: dict[str, dict[str, Any]]) -> None:
        self._buckets = buckets

    def list_buckets(self) -> dict[str, Any]:
        return {"Buckets": [{"Name": name} for name in self._buckets]}

    def get_bucket_location(self, Bucket: str) -> dict[str, Any]:  # noqa: N803
        spec = self._buckets[Bucket]
        if spec.get("location_raises"):
            raise _client_error()
        return {"LocationConstraint": spec.get("region")}

    def get_bucket_policy_status(self, Bucket: str) -> dict[str, Any]:  # noqa: N803
        spec = self._buckets[Bucket]
        if spec.get("policy_raises", True):
            raise _client_error()
        return {"PolicyStatus": {"IsPublic": spec.get("policy_is_public", False)}}

    def get_bucket_acl(self, Bucket: str) -> dict[str, Any]:  # noqa: N803
        spec = self._buckets[Bucket]
        if spec.get("acl_raises"):
            raise _client_error()
        return {"Grants": spec.get("acl_grants", [])}


async def test_buckets_are_inventoried_with_region_filtering_and_mixed_exposure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeListingClient(
        {
            # Public via bucket policy, in a scoped-in region.
            "public-by-policy": {
                "region": "us-west-2",
                "policy_raises": False,
                "policy_is_public": True,
            },
            # No policy; public via an ACL grant. LocationConstraint None
            # means us-east-1 (the S3 API's own convention).
            "public-by-acl": {
                "region": None,
                "policy_raises": True,
                "acl_grants": [
                    {
                        "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                        "Permission": "READ",
                    }
                ],
            },
            # Private, but outside the scoped regions — must be skipped
            # entirely, not merely reported as untested.
            "out-of-scope-region": {
                "region": "eu-west-1",
                "policy_raises": False,
                "policy_is_public": False,
            },
        }
    )
    monkeypatch.setattr(aws_module, "_client", lambda target, credential: client)

    target = CloudTarget(
        provider="aws",
        account_ref="123456789012",
        credential_env_var="AWS_CRED",
        allowed_regions=("us-west-2", "us-east-1"),
    )
    exposures = await list_exposed_storage(target, CREDENTIAL)

    by_name = {item.name: item for item in exposures}
    assert set(by_name) == {"public-by-policy", "public-by-acl"}
    assert by_name["public-by-policy"].is_public is True
    assert by_name["public-by-policy"].region == "us-west-2"
    assert by_name["public-by-acl"].is_public is True
    assert by_name["public-by-acl"].region == "us-east-1"


async def test_an_unscoped_target_lists_every_region(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeListingClient(
        {
            "bucket-a": {"region": "eu-west-1", "policy_raises": False, "policy_is_public": False},
            "bucket-b": {
                "region": "ap-south-1",
                "policy_raises": False,
                "policy_is_public": False,
            },
        }
    )
    monkeypatch.setattr(aws_module, "_client", lambda target, credential: client)

    exposures = await list_exposed_storage(TARGET, CREDENTIAL)

    assert {item.name for item in exposures} == {"bucket-a", "bucket-b"}
    assert all(item.is_public is False for item in exposures)


async def test_an_unreadable_bucket_location_falls_back_to_none_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeListingClient(
        {
            "bucket-a": {
                "location_raises": True,
                "policy_raises": False,
                "policy_is_public": False,
            },
        }
    )
    monkeypatch.setattr(aws_module, "_client", lambda target, credential: client)

    exposures = await list_exposed_storage(TARGET, CREDENTIAL)

    assert len(exposures) == 1
    assert exposures[0].region is None


async def test_rejected_credentials_are_a_cloud_provider_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _RejectingClient:
        def list_buckets(self) -> dict[str, Any]:
            raise botocore.exceptions.NoCredentialsError()

    monkeypatch.setattr(aws_module, "_client", lambda target, credential: _RejectingClient())

    with pytest.raises(CloudProviderError, match="AWS credentials were rejected"):
        await list_exposed_storage(TARGET, CREDENTIAL)


async def test_a_list_buckets_client_error_is_a_cloud_provider_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FailingClient:
        def list_buckets(self) -> dict[str, Any]:
            raise _client_error(code="AccessDenied")

    monkeypatch.setattr(aws_module, "_client", lambda target, credential: _FailingClient())

    with pytest.raises(CloudProviderError, match="AWS S3 ListBuckets failed"):
        await list_exposed_storage(TARGET, CREDENTIAL)


def test_a_missing_boto3_is_a_cloud_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(CloudProviderError, match="boto3 is not installed"):
        _list_exposed_storage_sync(TARGET, CREDENTIAL)


def test_a_missing_botocore_is_a_cloud_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "botocore.exceptions", None)
    with pytest.raises(CloudProviderError, match="boto3 is not installed"):
        _list_exposed_storage_sync(TARGET, CREDENTIAL)


# --- static: only read-only S3 verbs are ever called ---------------------------


def test_the_aws_provider_calls_only_read_only_s3_methods() -> None:
    """Static enforcement of this module's own guarantee — the same "no
    write verbs" discipline `docs/security-model.md` guarantee #20 applies
    to `app/core/vcs`'s pull-request layer."""
    allowed = {"list_buckets", "get_bucket_location", "get_bucket_policy_status", "get_bucket_acl"}
    source = inspect.getsource(aws_module)
    called = set(re.findall(r"\bclient\.([a-zA-Z_]+)\(", source))
    assert called, "expected to find at least one client.<method>(...) call"
    assert called <= allowed, f"unexpected S3 method call(s): {called - allowed}"
    forbidden_prefixes = ("put_", "delete_", "create_")
    assert not any(method.startswith(forbidden_prefixes) for method in called)
