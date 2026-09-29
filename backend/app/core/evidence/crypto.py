"""AES-256-GCM encryption for evidence bundles at rest (docs/BUILD_SPEC.md §13).

Optional, as the spec allows: a bundle is written encrypted only when
`KERVY_EVIDENCE_ENCRYPTION_KEY` is configured (`app/core/config.py`). Absent,
`EvidenceStore` writes exactly what it always wrote — the previously
honestly-stated gap in `app/core/evidence/store.py` stays the honest default,
not something silently half-solved by turning it on without asking.

**Key management, stated as plainly as before this existed:** one static
key, supplied by environment-variable value the same way `JWT_SECRET` and
`KERVY_CSRF_SECRET` already are — no rotation, no per-tenant key, no KMS
integration. Rotating it means re-encrypting every existing bundle by hand;
there is no tooling here for that. This is the same trade this project
already made for every other secret it holds (§17.2: referenced by
environment-variable name or value, never stored elsewhere), applied to one
more thing rather than a new model invented just for it.

**This deliberately does not do what §13's illustrative text describes**
("optional encryption-at-rest using a *run key* (age/libsodium)"). A
distinct key per run needs somewhere to keep each one — which, unless it is
itself wrapped by a master key (envelope encryption), is the exact
"operator believes it is protected while the key sits beside it" failure
the original deferral in `app/core/evidence/store.py` was refusing to ship.
Envelope encryption solves that at the cost of a second, harder problem: a
wrapping key with its own rotation, storage and compromise story, which
this platform has never needed for any other secret. One static key is a
narrower, honestly-scoped answer — everything this module actually protects
against (a stolen disk, a filesystem-level snapshot) is covered by it — not
an oversight of the spec's suggestion.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: AES-GCM's standard nonce size. Reusing a nonce with the same key breaks
#: confidentiality, so every call draws a fresh one and carries it with the
#: ciphertext — there is nowhere else on disk to keep it.
_NONCE_BYTES = 12


class DecryptionError(RuntimeError):
    """The blob does not decrypt under this key.

    Wrong key and altered ciphertext are indistinguishable by design: GCM's
    authentication tag fails the same way for both, and telling an attacker
    which one happened would leak information about the key.
    """


def encrypt(payload: bytes, *, key: bytes) -> bytes:
    """`nonce || ciphertext_with_tag`."""
    nonce = os.urandom(_NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, payload, None)


def decrypt(blob: bytes, *, key: bytes) -> bytes:
    if len(blob) < _NONCE_BYTES:
        raise DecryptionError("ciphertext shorter than one nonce; not a value this wrote")
    nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise DecryptionError("decryption failed: wrong key or altered ciphertext") from exc
