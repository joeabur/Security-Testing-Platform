"""`app/core/evidence/backends.py`'s `S3Backend` and the `build_evidence_store`
factory (docs/scaling-architecture.md's "no object-storage-backed evidence
store" gap).

`LocalFilesystemBackend` itself is already exercised end to end by every test
in `test_evidence.py` — this file is about what changed: the S3 backend's own
object-per-manifest-entry layout, and the factory that picks between the two.
Mirrors `test_cloud_aws.py`'s shape: a fake client standing in for `boto3`,
never a real AWS account.
"""

from __future__ import annotations

from typing import Any

import botocore.exceptions
import pytest

from app.core.config import Settings
from app.core.evidence.backends import EvidenceError, LocalFilesystemBackend, S3Backend
from app.core.evidence.bundle import build_bundle
from app.core.evidence.store import EvidenceStore, build_evidence_store


def _client_error(code: str = "404") -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError({"Error": {"Code": code, "Message": "nope"}}, "Op")


class _FakeBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class _FakeS3Client:
    """An in-memory stand-in for `boto3.client("s3")`.

    Keyed by the flat object key `S3Backend` computes, exactly like a real
    bucket — this is what lets the same `delete_objects`/`list_objects_v2`
    calls `S3Backend` makes be asserted against directly.
    """

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def head_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        if Key not in self.objects:
            raise _client_error("404")
        return {}

    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> dict[str, Any]:  # noqa: N803
        self.objects[Key] = Body
        return {}

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        if Key not in self.objects:
            raise _client_error("NoSuchKey")
        return {"Body": _FakeBody(self.objects[Key])}

    def list_objects_v2(
        self, *, Bucket: str, Prefix: str = "", ContinuationToken: str | None = None  # noqa: N803
    ) -> dict[str, Any]:
        matching = sorted(key for key in self.objects if key.startswith(Prefix))
        return {"Contents": [{"Key": key} for key in matching], "IsTruncated": False}

    def delete_objects(self, *, Bucket: str, Delete: dict[str, Any]) -> dict[str, Any]:  # noqa: N803
        for entry in Delete["Objects"]:
            self.objects.pop(entry["Key"], None)
        return {}


def _bundle(body: str = "hello", probe_id: str = "KERVY-TEST-S3-000") -> Any:
    return build_bundle(
        probe_id=probe_id,
        probe_version="1.0.0",
        method="GET",
        url="https://target.example.test/",
        response_body=body,
    )


# --- S3Backend, directly ---------------------------------------------------


def test_a_bundle_round_trips_through_s3() -> None:
    client = _FakeS3Client()
    backend = S3Backend("my-bucket", client=client)

    assert backend.bundle_exists("run-1", "sha256:" + "a" * 64) is False
    backend.write_bundle("run-1", "sha256:" + "a" * 64, b"payload")
    assert backend.bundle_exists("run-1", "sha256:" + "a" * 64) is True
    assert backend.read_bundle("run-1", "sha256:" + "a" * 64) == b"payload"


def test_reading_a_missing_bundle_is_an_evidence_error() -> None:
    backend = S3Backend("my-bucket", client=_FakeS3Client())
    with pytest.raises(EvidenceError, match="no evidence bundle"):
        backend.read_bundle("run-1", "sha256:" + "b" * 64)


def test_manifest_entries_read_back_in_sequence_order_regardless_of_write_order() -> None:
    """Each entry is its own object, keyed by sequence — proving the
    zero-padded key sort, not insertion order, is what determines the
    order `EvidenceStore`'s hash chain depends on."""
    backend = S3Backend("my-bucket", client=_FakeS3Client())
    backend.append_manifest_entry("run-1", 2, "third")
    backend.append_manifest_entry("run-1", 0, "first")
    backend.append_manifest_entry("run-1", 1, "second")

    assert backend.read_manifest_lines("run-1") == ["first", "second", "third"]


def test_run_exists_and_count_bundles() -> None:
    backend = S3Backend("my-bucket", client=_FakeS3Client())
    assert backend.run_exists("run-1") is False
    assert backend.count_bundles("run-1") == 0

    backend.write_bundle("run-1", "sha256:" + "a" * 64, b"one")
    backend.write_bundle("run-1", "sha256:" + "b" * 64, b"two")
    backend.append_manifest_entry("run-1", 0, "one-entry")

    assert backend.run_exists("run-1") is True
    # Only the bundle objects count — the manifest entry must not be
    # double-counted as a bundle.
    assert backend.count_bundles("run-1") == 2


def test_delete_run_removes_only_that_runs_objects() -> None:
    client = _FakeS3Client()
    backend = S3Backend("my-bucket", client=client)
    backend.write_bundle("run-1", "sha256:" + "a" * 64, b"one")
    backend.append_manifest_entry("run-1", 0, "entry")
    backend.write_bundle("run-2", "sha256:" + "b" * 64, b"other")

    backend.delete_run("run-1")

    assert backend.run_exists("run-1") is False
    assert backend.run_exists("run-2") is True


def test_a_prefix_keeps_runs_from_different_deployments_apart() -> None:
    client = _FakeS3Client()
    a = S3Backend("my-bucket", prefix="env-a/", client=client)
    b = S3Backend("my-bucket", prefix="env-b/", client=client)

    a.write_bundle("run-1", "sha256:" + "a" * 64, b"from-a")
    assert b.run_exists("run-1") is False
    assert a.run_exists("run-1") is True


def test_a_missing_boto3_is_an_evidence_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "boto3", None)
    backend = S3Backend("my-bucket")
    with pytest.raises(EvidenceError, match="boto3 is not installed"):
        backend.write_bundle("run-1", "sha256:" + "a" * 64, b"x")


# --- EvidenceStore, backed by S3 instead of the filesystem ------------------


def test_the_store_writes_reads_and_verifies_through_s3() -> None:
    store = EvidenceStore(backend=S3Backend("my-bucket", client=_FakeS3Client()))
    bundle = _bundle("original")
    digest = store.write("run-1", bundle)
    assert store.read("run-1", digest) == bundle.canonical_bytes()
    assert store.verify("run-1").ok


def test_writing_the_same_bundle_twice_does_not_extend_the_chain_on_s3() -> None:
    store = EvidenceStore(backend=S3Backend("my-bucket", client=_FakeS3Client()))
    bundle = _bundle("same")
    assert store.write("run-1", bundle) == store.write("run-1", bundle)
    assert len(store.read_manifest("run-1")) == 1


def test_editing_a_stored_bundle_breaks_verification_on_s3() -> None:
    client = _FakeS3Client()
    store = EvidenceStore(backend=S3Backend("my-bucket", client=client))
    digest = store.write("run-1", _bundle("original"))

    key = next(key for key in client.objects if digest.removeprefix("sha256:") in key)
    client.objects[key] = client.objects[key].replace(b"original", b"tampered")

    result = store.verify("run-1")
    assert not result.ok
    assert any("does not match its digest" in problem for problem in result.problems)


def test_removing_a_manifest_entry_breaks_the_chain_on_s3() -> None:
    client = _FakeS3Client()
    store = EvidenceStore(backend=S3Backend("my-bucket", client=client))
    store.write("run-1", _bundle("one"))
    store.write("run-1", _bundle("two", probe_id="KERVY-TEST-S3-001"))
    store.write("run-1", _bundle("three", probe_id="KERVY-TEST-S3-002"))

    manifest_key = next(key for key in sorted(client.objects) if "/manifest/" in key)
    del client.objects[manifest_key]

    result = store.verify("run-1")
    assert not result.ok
    assert any("chain broken" in problem for problem in result.problems)


def test_a_purge_actually_deletes_on_s3() -> None:
    client = _FakeS3Client()
    store = EvidenceStore(backend=S3Backend("my-bucket", client=client))
    store.write("run-1", _bundle("keep"))

    assert store.purge("run-1") == 1
    assert store.read_manifest("run-1") == []
    assert store.purge("run-1") == 0


def test_encryption_at_rest_still_works_through_s3() -> None:
    key = b"\x01" * 32
    store = EvidenceStore(backend=S3Backend("my-bucket", client=_FakeS3Client()), key=key)
    bundle = _bundle("secret-ish")
    digest = store.write("run-1", bundle)
    assert store.read("run-1", digest) == bundle.canonical_bytes()
    assert store.verify("run-1").ok


# --- EvidenceStore construction ---------------------------------------------


def test_the_store_requires_either_root_or_backend() -> None:
    with pytest.raises(ValueError, match="requires either root or backend"):
        EvidenceStore()


# --- build_evidence_store ----------------------------------------------------


def test_the_default_backend_is_local(tmp_path: Any) -> None:
    settings = Settings(JWT_SECRET="s", EVIDENCE_ROOT=str(tmp_path))  # pragma: allowlist secret
    store = build_evidence_store(settings)
    store.write("run-1", _bundle("on disk"))
    assert (tmp_path / "run-1" / "manifest.jsonl").exists()


def test_s3_backend_is_selected_when_configured() -> None:
    settings = Settings(
        JWT_SECRET="s",  # pragma: allowlist secret
        EVIDENCE_BACKEND="s3",
        EVIDENCE_S3_BUCKET="my-bucket",
    )
    store = build_evidence_store(settings)
    assert isinstance(store._backend, S3Backend)  # noqa: SLF001


def test_s3_backend_without_a_bucket_is_refused() -> None:
    settings = Settings(JWT_SECRET="s", EVIDENCE_BACKEND="s3")  # pragma: allowlist secret
    with pytest.raises(EvidenceError, match="EVIDENCE_S3_BUCKET"):
        build_evidence_store(settings)


def test_local_filesystem_backend_layout_is_unchanged(tmp_path: Any) -> None:
    """A direct check of `LocalFilesystemBackend`'s own layout, independent
    of `EvidenceStore` — the shape `test_evidence.py`'s tamper tests poke at
    by hand must still be exactly this."""
    backend = LocalFilesystemBackend(tmp_path)
    backend.write_bundle("run-1", "sha256:" + "a" * 64, b"payload")
    backend.append_manifest_entry("run-1", 0, "line-one")

    assert (tmp_path / "run-1" / "bundles" / ("a" * 64 + ".json")).read_bytes() == b"payload"
    assert (tmp_path / "run-1" / "manifest.jsonl").read_text() == "line-one\n"
