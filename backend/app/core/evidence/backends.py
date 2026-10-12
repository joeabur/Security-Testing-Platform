"""Where an `EvidenceStore` actually puts bytes (docs/BUILD_SPEC.md §13,
docs/scaling-architecture.md's "no object-storage-backed evidence store"
gap).

`EvidenceStore` itself only knows about bundles, digests and manifest
entries — never a filesystem path or an S3 key. Everything that touches a
real storage medium lives here, behind `StorageBackend`, so swapping one
for the other is a constructor argument, not a rewrite of the hash-chain
logic that makes evidence tamper-evident.

`LocalFilesystemBackend` is exactly what `EvidenceStore` always did to
`pathlib.Path` and `shutil`, moved here unchanged — same layout, same
calls, same behaviour. A few of `tests/test_evidence.py`'s tamper tests
poke at that layout directly (editing a bundle file, truncating the
manifest file by hand), so the local backend's on-disk shape is not free
to change; it is reproduced here rather than redesigned.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


class EvidenceError(RuntimeError):
    """Storage refused to write, or verification failed."""


@runtime_checkable
class StorageBackend(Protocol):
    """What `EvidenceStore` needs from wherever bundles actually live.

    Deliberately narrower than a generic filesystem or object-store
    interface: every method names the one operation `EvidenceStore` makes,
    so a new backend has a short, concrete contract to satisfy rather than
    an open-ended "implement a filesystem" task.
    """

    def bundle_exists(self, run_id: str, digest: str) -> bool: ...

    def write_bundle(self, run_id: str, digest: str, data: bytes) -> None: ...

    def read_bundle(self, run_id: str, digest: str) -> bytes: ...

    def append_manifest_entry(self, run_id: str, sequence: int, line: str) -> None: ...

    def read_manifest_lines(self, run_id: str) -> list[str]: ...

    def run_exists(self, run_id: str) -> bool: ...

    def count_bundles(self, run_id: str) -> int: ...

    def delete_run(self, run_id: str) -> None: ...


class LocalFilesystemBackend:
    """The only backend that existed before this module did.

    Layout, per run, under `root`::

        <root>/<run_id>/bundles/<sha256>.json    the bundle, named by its digest
        <root>/<run_id>/manifest.jsonl           one hash-chained entry per line
    """

    def __init__(self, root: Path) -> None:
        self._root = root

    def _run_dir(self, run_id: str) -> Path:
        return self._root / run_id

    def _bundles_dir(self, run_id: str) -> Path:
        return self._run_dir(run_id) / "bundles"

    def _manifest_path(self, run_id: str) -> Path:
        return self._run_dir(run_id) / "manifest.jsonl"

    def _bundle_path(self, run_id: str, digest: str) -> Path:
        return self._bundles_dir(run_id) / f"{digest.removeprefix('sha256:')}.json"

    def bundle_exists(self, run_id: str, digest: str) -> bool:
        return self._bundle_path(run_id, digest).exists()

    def write_bundle(self, run_id: str, digest: str, data: bytes) -> None:
        path = self._bundle_path(run_id, digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def read_bundle(self, run_id: str, digest: str) -> bytes:
        path = self._bundle_path(run_id, digest)
        if not path.exists():
            raise EvidenceError(f"no evidence bundle {digest} for run {run_id}")
        return path.read_bytes()

    def append_manifest_entry(self, run_id: str, sequence: int, line: str) -> None:
        # `sequence` is unused here: a local append needs no address of its
        # own, only the next line in the one file. S3Backend is the backend
        # that needs it.
        path = self._manifest_path(run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def read_manifest_lines(self, run_id: str) -> list[str]:
        path = self._manifest_path(run_id)
        if not path.exists():
            return []
        return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def run_exists(self, run_id: str) -> bool:
        return self._run_dir(run_id).exists()

    def count_bundles(self, run_id: str) -> int:
        return len(list(self._bundles_dir(run_id).glob("*.json")))

    def delete_run(self, run_id: str) -> None:
        shutil.rmtree(self._run_dir(run_id))


class S3Backend:
    """Object-storage evidence backend. Layout under `<prefix><run_id>/`::

        bundles/<sha256>.json         the bundle, named by its digest — same
                                       content-addressed idempotency as local
        manifest/<sequence:08d>.json  one object per hash-chain entry

    **Why the manifest is one object per entry, not one growing object.**
    S3 has no atomic append. Two probes finishing at nearly the same moment
    would each have to read the current manifest object, add a line, and
    put it back — and the second write to land would silently overwrite
    the first's entry, with neither call failing. A sequence-keyed object
    per entry turns "append" back into the same collision-free `put_object`
    the bundle files already are: `EvidenceStore` already knows the next
    sequence number before it writes (it is `len(existing entries)`), so
    this needs no new counter, lock service, or conditional-write dance.
    Zero-padded so a lexicographic key listing already comes back in
    sequence order.

    **Credentials and region are never a constructor argument here.**
    Unlike `app/core/cloud/providers/aws.py`'s per-*scanned-target* AWS
    provider, which resolves a credential the operator supplied for the
    system being assessed, this bucket belongs to the Kervy deployment
    itself. It is configured once by whoever runs this platform, so it
    uses `boto3`'s own standard credential and region resolution (an
    instance profile, `AWS_ACCESS_KEY_ID`/`AWS_DEFAULT_REGION`, or
    `~/.aws/config`) exactly the way any other AWS SDK call in this
    deployment's environment would, rather than inventing a second,
    narrower credential model for this one client.
    """

    def __init__(self, bucket: str, *, prefix: str = "", client: Any | None = None) -> None:
        self._bucket = bucket
        self._prefix = prefix
        self._client = client

    def _resolve_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3
        except ImportError as exc:
            raise EvidenceError(
                "boto3 is not installed on this worker — install the platform's "
                "'cloud' extra to enable the S3 evidence backend"
            ) from exc
        self._client = boto3.client("s3")
        return self._client

    @staticmethod
    def _client_error_type() -> type[Exception]:
        try:
            import botocore.exceptions
        except ImportError as exc:
            raise EvidenceError(
                "boto3 is not installed on this worker — install the platform's "
                "'cloud' extra to enable the S3 evidence backend"
            ) from exc
        return botocore.exceptions.ClientError  # type: ignore[no-any-return]

    @staticmethod
    def _is_not_found(exc: Exception) -> bool:
        response = getattr(exc, "response", None)
        if not isinstance(response, dict):
            return False
        code = response.get("Error", {}).get("Code")
        return code in {"404", "NoSuchKey", "NotFound"}

    def _key(self, run_id: str, *parts: str) -> str:
        return f"{self._prefix}{run_id}/" + "/".join(parts)

    def _bundle_key(self, run_id: str, digest: str) -> str:
        return self._key(run_id, "bundles", f"{digest.removeprefix('sha256:')}.json")

    def _manifest_key(self, run_id: str, sequence: int) -> str:
        return self._key(run_id, "manifest", f"{sequence:08d}.json")

    def _manifest_prefix(self, run_id: str) -> str:
        return self._key(run_id, "manifest") + "/"

    def _run_prefix(self, run_id: str) -> str:
        return f"{self._prefix}{run_id}/"

    def _list_keys(self, prefix: str) -> list[str]:
        client = self._resolve_client()
        keys: list[str] = []
        continuation: str | None = None
        while True:
            kwargs: dict[str, Any] = {"Bucket": self._bucket, "Prefix": prefix}
            if continuation:
                kwargs["ContinuationToken"] = continuation
            response = client.list_objects_v2(**kwargs)
            keys.extend(obj["Key"] for obj in response.get("Contents", []))
            if not response.get("IsTruncated"):
                return keys
            continuation = response.get("NextContinuationToken")

    def bundle_exists(self, run_id: str, digest: str) -> bool:
        client = self._resolve_client()
        client_error = self._client_error_type()
        try:
            client.head_object(Bucket=self._bucket, Key=self._bundle_key(run_id, digest))
            return True
        except client_error as exc:
            if self._is_not_found(exc):
                return False
            raise EvidenceError(f"S3 HeadObject failed for bundle {digest}: {exc}") from exc

    def write_bundle(self, run_id: str, digest: str, data: bytes) -> None:
        client = self._resolve_client()
        client_error = self._client_error_type()
        try:
            client.put_object(Bucket=self._bucket, Key=self._bundle_key(run_id, digest), Body=data)
        except client_error as exc:
            raise EvidenceError(f"S3 PutObject failed for bundle {digest}: {exc}") from exc

    def read_bundle(self, run_id: str, digest: str) -> bytes:
        client = self._resolve_client()
        client_error = self._client_error_type()
        try:
            response = client.get_object(Bucket=self._bucket, Key=self._bundle_key(run_id, digest))
        except client_error as exc:
            if self._is_not_found(exc):
                raise EvidenceError(f"no evidence bundle {digest} for run {run_id}") from exc
            raise EvidenceError(f"S3 GetObject failed for bundle {digest}: {exc}") from exc
        return response["Body"].read()  # type: ignore[no-any-return]

    def append_manifest_entry(self, run_id: str, sequence: int, line: str) -> None:
        client = self._resolve_client()
        client_error = self._client_error_type()
        try:
            client.put_object(
                Bucket=self._bucket,
                Key=self._manifest_key(run_id, sequence),
                Body=line.encode("utf-8"),
            )
        except client_error as exc:
            raise EvidenceError(
                f"S3 PutObject failed for manifest entry {sequence}: {exc}"
            ) from exc

    def read_manifest_lines(self, run_id: str) -> list[str]:
        client = self._resolve_client()
        client_error = self._client_error_type()
        # Zero-padded sequence numbers sort lexicographically in the same
        # order as numerically, so the key listing is already in order.
        keys = sorted(self._list_keys(self._manifest_prefix(run_id)))
        lines: list[str] = []
        try:
            for key in keys:
                body = client.get_object(Bucket=self._bucket, Key=key)["Body"].read()
                lines.append(body.decode("utf-8"))
        except client_error as exc:
            raise EvidenceError(f"S3 GetObject failed reading the manifest: {exc}") from exc
        return lines

    def run_exists(self, run_id: str) -> bool:
        return bool(self._list_keys(self._run_prefix(run_id)))

    def count_bundles(self, run_id: str) -> int:
        return len(self._list_keys(self._key(run_id, "bundles") + "/"))

    def delete_run(self, run_id: str) -> None:
        client = self._resolve_client()
        client_error = self._client_error_type()
        keys = self._list_keys(self._run_prefix(run_id))
        try:
            # S3's DeleteObjects takes at most 1000 keys per call.
            for start in range(0, len(keys), 1000):
                batch = keys[start : start + 1000]
                client.delete_objects(
                    Bucket=self._bucket, Delete={"Objects": [{"Key": key} for key in batch]}
                )
        except client_error as exc:
            raise EvidenceError(f"S3 DeleteObjects failed for run {run_id}: {exc}") from exc
