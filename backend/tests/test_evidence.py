"""Evidence bundles and the evidence store (docs/BUILD_SPEC.md §13).

The property test is the one that matters. Everything else here checks a
specific mechanism; `test_no_secret_survives_bundling` checks the invariant
those mechanisms exist to uphold — that no path through `build_bundle` can
produce a bundle which still discloses a credential. It is a property test
rather than a list of examples because the interesting failures are the
inputs nobody thought to write down.
"""

import json
import shutil
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.core.evidence.bundle import (
    ALWAYS_MASKED_HEADERS,
    MASK,
    MAX_BODY_CHARS,
    build_bundle,
    contains_secret,
    mask_headers,
)
from app.core.evidence.store import (
    CHAIN_GENESIS,
    EvidenceBundle,
    EvidenceError,
    EvidenceStore,
)

# Credential shapes the detectors recognise, written to match the real
# formats so the test exercises the patterns rather than a placeholder.
SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_" + "a" * 36,
    "sk-proj-" + "B" * 32,
    "AIza" + "c" * 35,
    "sk_live_" + "d" * 24,
    "xoxb-1234567890-abcdefghij",  # pragma: allowlist secret
    "postgresql://kervy:sup3rs3cretpassw0rd@db.internal:5432/app",
    # pragma: allowlist nextline secret
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g",
    # pragma: allowlist nextline secret
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
]

_TEXT = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=0x2FFF, blacklist_categories=("Cs",)),
    max_size=200,
)


# --- the invariant -------------------------------------------------------


@settings(max_examples=250, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(
    prefix=_TEXT,
    suffix=_TEXT,
    secret=st.sampled_from(SECRETS),
    header_name=st.sampled_from(["X-Trace", "User-Agent", "X-Correlation-Id", "Authorization"]),
    in_request=st.booleans(),
)
def test_no_secret_survives_bundling(
    prefix: str, suffix: str, secret: str, header_name: str, in_request: bool
) -> None:
    """Whatever the surrounding text, a credential never reaches the bundle.

    The secret is planted in a body and a header, wrapped in arbitrary text,
    on either side of the exchange. The assertion is on the serialized bytes
    — the thing that would actually be written to disk — not on a field.
    """
    tainted = f"{prefix}{secret}{suffix}"
    bundle = build_bundle(
        probe_id="KERVY-TEST-001",
        probe_version="1.0.0",
        method="POST",
        url="https://target.example.test/api/chat",
        request_headers={header_name: tainted} if in_request else {"X-Trace": prefix},
        request_body=tainted if in_request else prefix,
        status_code=200,
        response_headers={header_name: tainted} if not in_request else {"X-Trace": suffix},
        response_body=tainted if not in_request else suffix,
        detector_verdict="marker observed",
        judge_transcript=tainted,
    )
    payload = bundle.canonical_bytes()

    assert secret not in payload.decode()
    assert not contains_secret(payload)
    # And the bundle says a redaction happened, so a reader knows the gap is
    # deliberate rather than an empty field.
    assert bundle.redactions


@settings(
    max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(body=_TEXT)
def test_a_bundle_the_store_accepts_is_one_that_verifies(body: str) -> None:
    """Writing is not allowed to change content. If it did, the digest in the
    manifest would stop matching the file and the chain would be worthless.

    Its own temporary directory per example rather than `tmp_path`, which
    hypothesis rightly refuses to reuse across examples.
    """
    root = Path(tempfile.mkdtemp())
    store = EvidenceStore(root / "e")
    bundle = build_bundle(
        probe_id="KERVY-TEST-002",
        probe_version="1.0.0",
        method="GET",
        url="https://target.example.test/",
        response_body=body,
    )
    try:
        digest = store.write("run-prop", bundle)
        assert store.read("run-prop", digest) == bundle.canonical_bytes()
        assert store.verify("run-prop").ok
    finally:
        shutil.rmtree(root, ignore_errors=True)


# --- redaction mechanics -------------------------------------------------


@pytest.mark.parametrize("header", sorted(ALWAYS_MASKED_HEADERS))
def test_credential_headers_are_masked_by_name_whatever_they_contain(header: str) -> None:
    """Not scanned — masked. A bearer token that no pattern matches is still
    a bearer token, and the header name alone is enough to know that."""
    masked, _ = mask_headers({header.title(): "anything-at-all"})
    assert list(masked.values()) == [MASK]


def test_a_secret_in_an_unexpected_header_is_still_caught() -> None:
    masked, matches = mask_headers({"X-Debug-Config": "token=ghp_" + "e" * 36})
    assert "ghp_" not in masked["X-Debug-Config"]
    assert [m.kind for m in matches] == ["github_token"]


def test_a_redaction_records_a_digest_so_two_sightings_can_be_correlated() -> None:
    """§13: a redacted value is replaced by a hash, not deleted. Analysts
    need to know "the same credential appeared in both" without holding it."""
    first = build_bundle(
        probe_id="KERVY-TEST-003",
        probe_version="1.0.0",
        method="GET",
        url="https://target.example.test/",
        response_body="key=AKIAIOSFODNN7EXAMPLE",
    )
    second = build_bundle(
        probe_id="KERVY-TEST-004",
        probe_version="1.0.0",
        method="GET",
        url="https://target.example.test/other",
        response_body="AKIAIOSFODNN7EXAMPLE was here",
    )
    assert first.redactions[0]["sha256"] == second.redactions[0]["sha256"]
    # The preview keeps the four-character issuer prefix on purpose — it says
    # *which kind* of credential leaked, which is what an operator needs — and
    # nothing else. The value itself is gone.
    serialized = json.dumps(first.redactions)
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized
    assert "AKIA********" in serialized


def test_an_enormous_body_is_truncated_before_it_is_stored() -> None:
    bundle = build_bundle(
        probe_id="KERVY-TEST-005",
        probe_version="1.0.0",
        method="GET",
        url="https://target.example.test/",
        response_body="x" * (MAX_BODY_CHARS * 3),
    )
    assert len(bundle.response["body"]) <= MAX_BODY_CHARS


# --- the store -----------------------------------------------------------


def _bundle(body: str = "hello", probe_id: str = "KERVY-TEST-010") -> EvidenceBundle:
    return build_bundle(
        probe_id=probe_id,
        probe_version="1.0.0",
        method="GET",
        url="https://target.example.test/",
        response_body=body,
    )


def test_the_chain_starts_from_a_documented_genesis(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    store.write("run-1", _bundle())
    entries = store.read_manifest("run-1")
    assert entries[0].previous == CHAIN_GENESIS
    assert store.verify("run-1").ok


def test_writing_the_same_bundle_twice_does_not_extend_the_chain(
    tmp_path: Path,
) -> None:
    """Content addressing makes a re-write idempotent.

    Note what this does *not* claim: two separately observed exchanges that
    happen to be byte-identical are still two bundles, because each carries
    its own `created_at`. They were two trials, and a manifest that showed
    one would understate the measurement.
    """
    store = EvidenceStore(tmp_path)
    bundle = _bundle("same")
    assert store.write("run-2", bundle) == store.write("run-2", bundle)
    assert len(store.read_manifest("run-2")) == 1

    store.write("run-2", _bundle("same"))
    assert len(store.read_manifest("run-2")) == 2
    assert store.verify("run-2").ok


def test_editing_a_stored_bundle_breaks_verification(tmp_path: Path) -> None:
    """The reason the chain exists. Verification has to fail on a file that
    was changed after it was written, not merely on a missing one."""
    store = EvidenceStore(tmp_path)
    digest = store.write("run-3", _bundle("original"))
    store.write("run-3", _bundle("second", probe_id="KERVY-TEST-011"))

    path = tmp_path / "run-3" / "bundles" / f"{digest.removeprefix('sha256:')}.json"
    path.write_text(path.read_text().replace("original", "tampered"), encoding="utf-8")

    result = store.verify("run-3")
    assert not result.ok
    assert any("does not match its digest" in problem for problem in result.problems)


def test_removing_a_manifest_entry_breaks_the_chain(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path)
    store.write("run-4", _bundle("one"))
    store.write("run-4", _bundle("two", probe_id="KERVY-TEST-012"))
    store.write("run-4", _bundle("three", probe_id="KERVY-TEST-013"))

    manifest = tmp_path / "run-4" / "manifest.jsonl"
    lines = manifest.read_text(encoding="utf-8").splitlines()
    manifest.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")

    result = store.verify("run-4")
    assert not result.ok
    assert any("chain broken" in problem for problem in result.problems)


def test_the_store_refuses_a_bundle_that_was_not_redacted(tmp_path: Path) -> None:
    """The last line of defence. A bundle assembled by hand, bypassing
    `build_bundle`, must not be written — silently storing it would make the
    redaction guarantee depend on every future caller remembering."""
    store = EvidenceStore(tmp_path)
    raw = EvidenceBundle(
        probe_id="KERVY-TEST-020",
        probe_version="1.0.0",
        request={"method": "GET", "url": "https://t.test/", "headers": {}, "body": ""},
        response={"status_code": 200, "headers": {}, "body": "AKIAIOSFODNN7EXAMPLE"},
        timing_ms=1.0,
    )
    with pytest.raises(EvidenceError, match="refusing to write"):
        store.write("run-5", raw)
    assert store.read_manifest("run-5") == []


def test_a_purge_actually_deletes(tmp_path: Path) -> None:
    """§13 says a genuine delete. Hiding rows while the bytes remain is the
    failure mode a retention promise usually has."""
    store = EvidenceStore(tmp_path)
    store.write("run-6", _bundle("keep"))
    assert store.purge("run-6") == 1
    assert not (tmp_path / "run-6").exists()
    assert store.read_manifest("run-6") == []
    assert store.purge("run-6") == 0


# --- encryption at rest (§13) ----------------------------------------------

_KEY = b"\x01" * 32
_OTHER_KEY = b"\x02" * 32


def test_an_unconfigured_store_writes_plaintext_to_disk(tmp_path: Path) -> None:
    """The default, unchanged by encryption existing as an option."""
    store = EvidenceStore(tmp_path)
    digest = store.write("run-enc-0", _bundle("in the clear"))
    path = tmp_path / "run-enc-0" / "bundles" / f"{digest.removeprefix('sha256:')}.json"
    assert b"in the clear" in path.read_bytes()


def test_a_configured_store_does_not_write_plaintext_to_disk(tmp_path: Path) -> None:
    """The property that makes this an encryption-at-rest control rather than
    a checkbox: the bytes on disk must not contain the plaintext."""
    store = EvidenceStore(tmp_path, key=_KEY)
    digest = store.write("run-enc-1", _bundle("secret-shaped-but-not-a-credential"))
    path = tmp_path / "run-enc-1" / "bundles" / f"{digest.removeprefix('sha256:')}.json"
    assert b"secret-shaped-but-not-a-credential" not in path.read_bytes()


def test_reading_back_a_configured_store_returns_the_original_plaintext(
    tmp_path: Path,
) -> None:
    """The other half: encryption must be transparent to a caller of `read`."""
    store = EvidenceStore(tmp_path, key=_KEY)
    bundle = _bundle("round trip")
    digest = store.write("run-enc-2", bundle)
    assert store.read("run-enc-2", digest) == bundle.canonical_bytes()


def test_verification_still_works_through_encryption(tmp_path: Path) -> None:
    """The chain has to keep meaning what it always meant, encrypted or not —
    digests are computed over plaintext, so this must not silently start
    comparing ciphertext to a plaintext digest."""
    store = EvidenceStore(tmp_path, key=_KEY)
    store.write("run-enc-3", _bundle("one"))
    store.write("run-enc-3", _bundle("two", probe_id="KERVY-TEST-030"))
    assert store.verify("run-enc-3").ok


def test_the_wrong_key_cannot_read_an_encrypted_bundle(tmp_path: Path) -> None:
    """Encryption that any key could undo would not be encryption. Verified
    at the level a caller actually hits: `read`, not just the primitive."""
    writer = EvidenceStore(tmp_path, key=_KEY)
    digest = writer.write("run-enc-4", _bundle("only for the right key"))

    reader = EvidenceStore(tmp_path, key=_OTHER_KEY)
    with pytest.raises(EvidenceError, match="could not decrypt"):
        reader.read("run-enc-4", digest)


def test_verify_reports_the_wrong_key_as_a_problem_not_a_crash(tmp_path: Path) -> None:
    writer = EvidenceStore(tmp_path, key=_KEY)
    writer.write("run-enc-5", _bundle("wrong reader"))

    reader = EvidenceStore(tmp_path, key=_OTHER_KEY)
    result = reader.verify("run-enc-5")
    assert not result.ok
    assert any("bundle" in problem for problem in result.problems)


def test_a_tampered_encrypted_bundle_fails_to_decrypt_rather_than_lying(
    tmp_path: Path,
) -> None:
    """GCM's authentication tag is what makes 'decrypts cleanly' a genuine
    integrity claim, not merely a confidentiality one — flip a byte and this
    must refuse to produce any plaintext at all, not a corrupted one."""
    store = EvidenceStore(tmp_path, key=_KEY)
    digest = store.write("run-enc-6", _bundle("tamper target"))
    path = tmp_path / "run-enc-6" / "bundles" / f"{digest.removeprefix('sha256:')}.json"

    on_disk = bytearray(path.read_bytes())
    on_disk[-1] ^= 0xFF
    path.write_bytes(bytes(on_disk))

    with pytest.raises(EvidenceError, match="could not decrypt"):
        store.read("run-enc-6", digest)


def test_encrypting_the_same_payload_twice_produces_different_ciphertext(
    tmp_path: Path,
) -> None:
    """A fresh nonce per write — reusing one under the same key would leak
    whether two bundles share content by making their ciphertexts match."""
    from app.core.evidence.crypto import encrypt

    payload = b"identical plaintext"
    assert encrypt(payload, key=_KEY) != encrypt(payload, key=_KEY)
