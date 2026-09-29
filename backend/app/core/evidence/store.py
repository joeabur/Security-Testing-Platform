"""Content-addressed evidence storage with a hash-chained manifest
(docs/BUILD_SPEC.md §13).

Layout, per run:

    <root>/<run_id>/bundles/<sha256>.json    the bundle, named by its digest
    <root>/<run_id>/manifest.jsonl           one hash-chained entry per bundle

The chain is the point. Each manifest entry carries the previous entry's
digest, so an altered or removed bundle breaks verification at a specific
entry rather than passing unnoticed. That is what makes "this evidence is
what the tool saw" a checkable claim instead of an assurance.

**Encryption at rest is optional, per §13.** Configuring
`KERVY_EVIDENCE_ENCRYPTION_KEY` (`app/core/config.py`) encrypts every bundle
written from then on with AES-256-GCM (`app/core/evidence/crypto.py`) before
it touches disk; without it, a bundle is written exactly as it always was,
protected by filesystem permissions and the redaction that ran before it was
built. `docs/roadmap.md` records the key model this uses and, deliberately,
does not claim to solve: one static key, no rotation, no per-tenant key.

**Turning the key on after bundles already exist does not retrofit them.**
A bundle written before the key was configured is plaintext on disk; `read`
and `verify` for that bundle, once a key is configured, attempt to decrypt
plaintext bytes and fail (`EvidenceError` / a verify problem) rather than
silently returning garbage. There is no migration tool to re-encrypt
existing bundles in place — the key is meant to be set before a deployment
starts collecting evidence, not switched on mid-run.
"""

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from app.core.evidence.bundle import EvidenceBundle, secret_kinds
from app.core.evidence.crypto import DecryptionError, decrypt, encrypt

# The first entry's "previous" value. A fixed, documented starting point,
# so a chain of length one is still verifiable.
CHAIN_GENESIS = "sha256:" + "0" * 64


class EvidenceError(RuntimeError):
    """Storage refused to write, or verification failed."""


@dataclass(frozen=True)
class ManifestEntry:
    sequence: int
    digest: str
    previous: str
    chain: str
    probe_id: str
    created_at: str

    @classmethod
    def compute_chain(cls, *, previous: str, digest: str, sequence: int) -> str:
        return "sha256:" + hashlib.sha256(f"{previous}|{digest}|{sequence}".encode()).hexdigest()


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    entries: int
    problems: tuple[str, ...] = ()


class EvidenceStore:
    def __init__(self, root: Path, *, key: bytes | None = None) -> None:
        #: `None` means bundles are written and read as plaintext — the
        #: default, and the only option before encryption at rest existed.
        self._root = root
        self._key = key

    def run_dir(self, run_id: str) -> Path:
        return self._root / run_id

    def _bundles_dir(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "bundles"

    def _manifest_path(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "manifest.jsonl"

    def write(self, run_id: str, bundle: EvidenceBundle) -> str:
        """Store a bundle and extend the chain. Returns its digest."""
        payload = bundle.canonical_bytes()

        # Last line of defence. `build_bundle` already redacted; if a secret
        # still reaches here, something constructed a bundle another way and
        # the write is refused rather than completed.
        leaked = secret_kinds(payload, ignore=bundle.canaries)
        if leaked:
            raise EvidenceError(
                "refusing to write an evidence bundle that still contains a "
                f"credential-shaped value ({', '.join(leaked)}); bundles must be "
                "built through build_bundle(), which redacts before serialization"
            )

        digest = bundle.digest()
        bundles = self._bundles_dir(run_id)
        bundles.mkdir(parents=True, exist_ok=True)
        path = bundles / f"{digest.removeprefix('sha256:')}.json"

        # Content-addressed, which makes a re-write idempotent: the same
        # bundle written twice — a retried write, or a probe that records its
        # observation on two code paths — is one file and one chain entry.
        #
        # `created_at` is part of the content, so two *separate* observations
        # of an identical exchange remain two bundles. That is deliberate:
        # they are two trials, and collapsing them would quietly understate
        # what the measurement was based on.
        if path.exists():
            return digest
        # Content addressing and the chain both key off the *plaintext*
        # digest — encryption is something that happens to the bytes on
        # disk, not a second identity for the same observation.
        on_disk = encrypt(payload, key=self._key) if self._key else payload
        path.write_bytes(on_disk)

        entries = self.read_manifest(run_id)
        previous = entries[-1].chain if entries else CHAIN_GENESIS
        sequence = len(entries)
        entry = ManifestEntry(
            sequence=sequence,
            digest=digest,
            previous=previous,
            chain=ManifestEntry.compute_chain(previous=previous, digest=digest, sequence=sequence),
            probe_id=bundle.probe_id,
            created_at=bundle.created_at,
        )
        with self._manifest_path(run_id).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry.__dict__, sort_keys=True) + "\n")
        return digest

    def read_manifest(self, run_id: str) -> list[ManifestEntry]:
        path = self._manifest_path(run_id)
        if not path.exists():
            return []
        entries: list[ManifestEntry] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(ManifestEntry(**json.loads(line)))
        return entries

    def read(self, run_id: str, digest: str) -> bytes:
        """Plaintext bytes, regardless of whether this store is configured
        with a key — a caller should never need to know that to read a
        bundle back."""
        path = self._bundles_dir(run_id) / f"{digest.removeprefix('sha256:')}.json"
        if not path.exists():
            raise EvidenceError(f"no evidence bundle {digest} for run {run_id}")
        on_disk = path.read_bytes()
        if not self._key:
            return on_disk
        try:
            return decrypt(on_disk, key=self._key)
        except DecryptionError as exc:
            raise EvidenceError(f"could not decrypt evidence bundle {digest}: {exc}") from exc

    def verify(self, run_id: str) -> VerificationResult:
        """Check every link and every bundle's content against its name.

        Both halves matter: the chain catches a removed or reordered entry,
        and re-hashing the file catches one whose bytes were edited in place.
        """
        entries = self.read_manifest(run_id)
        problems: list[str] = []
        previous = CHAIN_GENESIS

        for index, entry in enumerate(entries):
            if entry.sequence != index:
                problems.append(f"entry {index}: sequence is {entry.sequence}")
            if entry.previous != previous:
                problems.append(
                    f"entry {index}: chain broken — expected previous {previous}, "
                    f"found {entry.previous}"
                )
            expected = ManifestEntry.compute_chain(
                previous=entry.previous, digest=entry.digest, sequence=entry.sequence
            )
            if entry.chain != expected:
                problems.append(f"entry {index}: chain value does not match its inputs")

            path = self._bundles_dir(run_id) / f"{entry.digest.removeprefix('sha256:')}.json"
            if not path.exists():
                problems.append(f"entry {index}: bundle {entry.digest} is missing")
            else:
                on_disk = path.read_bytes()
                if self._key:
                    try:
                        plaintext = decrypt(on_disk, key=self._key)
                    except DecryptionError as exc:
                        problems.append(f"entry {index}: bundle {entry.digest} — {exc}")
                        previous = entry.chain
                        continue
                else:
                    plaintext = on_disk
                actual = "sha256:" + hashlib.sha256(plaintext).hexdigest()
                if actual != entry.digest:
                    problems.append(
                        f"entry {index}: bundle content does not match its digest "
                        "(the file was modified after it was written)"
                    )
            previous = entry.chain

        return VerificationResult(ok=not problems, entries=len(entries), problems=tuple(problems))

    def purge(self, run_id: str) -> int:
        """Delete a run's evidence for real.

        §13 says "performs a genuine delete". Removing the directory rather
        than marking rows hidden is the difference between a retention
        promise that is kept and one that is described. The manifest goes
        with it: a chain over deleted bundles would verify as broken forever
        and tell a reader nothing useful.
        """
        directory = self.run_dir(run_id)
        if not directory.exists():
            return 0
        count = len(list(self._bundles_dir(run_id).glob("*.json")))
        shutil.rmtree(directory)
        return count
