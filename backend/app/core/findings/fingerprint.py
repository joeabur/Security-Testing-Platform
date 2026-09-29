"""Finding identity across runs (docs/BUILD_SPEC.md §11).

The fingerprint is `probe_id + normalized surface + canonicalized evidence
signature` — and §11 is explicit that it is **not** response text.

That exclusion is the whole design. A model's reply differs on every call, a
timestamp appears in half of them, and a request id in the rest. Fingerprint
on any of that and the same unfixed weakness becomes a new finding every
run: the history is destroyed, "is this still there?" becomes unanswerable,
and a remediation workflow has nothing stable to attach to.

So the signature is built from the *shape* of what was found — the surface
and the structural facts a probe chose to record — with volatile detail
removed by normalization rather than by hope.
"""

import hashlib
import re

# Things that legitimately appear in a surface or an evidence signature and
# differ every run. Replaced with a placeholder rather than dropped, so a
# path with an id stays distinguishable from one without.
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
# Eight characters, not sixteen: request ids, correlation ids and short
# git SHAs are all this length and all differ every run. The cost is that
# an eight-letter word made only of a-f is normalized too, which is a
# price worth paying to keep one weakness as one finding.
_HEX = re.compile(r"\b[0-9a-f]{8,}\b", re.I)
_LONG_NUMBER = re.compile(r"\b\d{4,}\b")
_TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z?\b")
_CANARY = re.compile(r"KERVY-CANARY-[0-9A-F]+", re.I)
_WHITESPACE = re.compile(r"\s+")


def normalize_surface(surface: str) -> str:
    """Reduce a surface to what identifies it rather than what instantiated it.

    `GET /api/orders/9f3a-…` and `GET /api/orders/{order_id}` are the same
    surface; treating them as different would file one finding per object id
    the scan happened to touch.
    """
    text = surface.strip()
    text = _UUID.sub("{id}", text)
    # A path segment that is entirely digits is an identifier, not a route.
    text = re.sub(r"(?<=/)\d+(?=/|$)", "{id}", text)
    text = _HEX.sub("{hex}", text)
    return _WHITESPACE.sub(" ", text).rstrip("/") or "/"


def evidence_signature(*parts: str) -> str:
    """A canonical signature from the structural facts a probe recorded.

    Callers pass the *stable* parts — a rule id, a blocked rule, a sink
    name, a declared field — never a response body. Run-specific tokens that
    slip through are normalized out here as a second line of defence: a
    canary marker is random per run by design, so leaving one in would
    guarantee a new fingerprint every time.
    """
    joined = " ".join(part.strip() for part in parts if part and part.strip())
    joined = _CANARY.sub("{canary}", joined)
    joined = _TIMESTAMP.sub("{timestamp}", joined)
    joined = _UUID.sub("{id}", joined)
    joined = _HEX.sub("{hex}", joined)
    joined = _LONG_NUMBER.sub("{n}", joined)
    return _WHITESPACE.sub(" ", joined).strip().lower()


def fingerprint(*, probe_id: str, surface: str, signature: str) -> str:
    material = f"{probe_id}|{normalize_surface(surface)}|{evidence_signature(signature)}"
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()
