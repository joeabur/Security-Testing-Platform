"""Licence classification, by SPDX identifier.

The table below is a *risk posture*, not legal advice, and the distinction is
load-bearing: what counts as acceptable depends on whether the product ships as
a binary, runs as a hosted service, or is itself open source. So the engine
reports the obligation a licence carries and leaves the decision to a human,
rather than emitting a "violation" nobody agreed the rules for.

Categories:

* `network_copyleft` — AGPL and friends. Triggers on *use over a network*, which
  is the case a SaaS team most often does not expect.
* `strong_copyleft` — GPL: derivative works must be released under the same terms.
* `weak_copyleft` — LGPL, MPL, EPL: file- or library-level obligations, usually
  satisfiable by dynamic linking and publishing modifications.
* `permissive` — MIT, BSD, Apache: attribution, and for Apache a patent grant.
* `public_domain` — CC0, Unlicense.
* `proprietary_or_unknown` — anything unrecognised, **including a missing
  licence**. Missing is not permissive, and the engine never treats it as such.
"""

from __future__ import annotations

import re
from enum import StrEnum


class LicenseRisk(StrEnum):
    PUBLIC_DOMAIN = "public_domain"
    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    NETWORK_COPYLEFT = "network_copyleft"
    PROPRIETARY_OR_UNKNOWN = "proprietary_or_unknown"


#: `ScanResult.frameworks` tag `LicenseRiskEngine` attaches to each finding it
#: reports, carrying the band it classified. There is no dedicated schema
#: field for this anywhere in the findings pipeline — `frameworks` already
#: flows through unchanged to `Finding.mappings["other"]` and from there to
#: the findings API `kervy-ai gate` reads, which is what lets the gate match
#: on a licence band (`GateConfig.forbidden_license_bands`) without a
#: migration. Kept here, next to `LicenseRisk` itself, so the engine and the
#: gate both read the one definition rather than each spelling the prefix out.
LICENSE_BAND_FRAMEWORK_PREFIX = "LICENSE-BAND:"


#: SPDX identifiers, lowercased, without the `-only`/`-or-later` suffix which is
#: stripped before lookup. Not exhaustive and not meant to be: an identifier
#: that is not here lands in `proprietary_or_unknown`, which is the safe way to
#: be wrong.
_BY_ID: dict[str, LicenseRisk] = {
    "cc0-1.0": LicenseRisk.PUBLIC_DOMAIN,
    "unlicense": LicenseRisk.PUBLIC_DOMAIN,
    "0bsd": LicenseRisk.PUBLIC_DOMAIN,
    "mit": LicenseRisk.PERMISSIVE,
    "mit-0": LicenseRisk.PERMISSIVE,
    "isc": LicenseRisk.PERMISSIVE,
    "bsd-2-clause": LicenseRisk.PERMISSIVE,
    "bsd-3-clause": LicenseRisk.PERMISSIVE,
    "apache-2.0": LicenseRisk.PERMISSIVE,
    "python-2.0": LicenseRisk.PERMISSIVE,
    "psf-2.0": LicenseRisk.PERMISSIVE,
    "zlib": LicenseRisk.PERMISSIVE,
    "lgpl-2.1": LicenseRisk.WEAK_COPYLEFT,
    "lgpl-3.0": LicenseRisk.WEAK_COPYLEFT,
    "mpl-2.0": LicenseRisk.WEAK_COPYLEFT,
    "epl-2.0": LicenseRisk.WEAK_COPYLEFT,
    "cddl-1.0": LicenseRisk.WEAK_COPYLEFT,
    "gpl-2.0": LicenseRisk.STRONG_COPYLEFT,
    "gpl-3.0": LicenseRisk.STRONG_COPYLEFT,
    "agpl-3.0": LicenseRisk.NETWORK_COPYLEFT,
    "osl-3.0": LicenseRisk.NETWORK_COPYLEFT,
    "sspl-1.0": LicenseRisk.NETWORK_COPYLEFT,
    "elastic-2.0": LicenseRisk.PROPRIETARY_OR_UNKNOWN,
    "bsl-1.1": LicenseRisk.PROPRIETARY_OR_UNKNOWN,
}

_SUFFIX = re.compile(r"-(?:only|or-later)$")
_NOISE = re.compile(r"[\s\"']+")

OBLIGATIONS: dict[LicenseRisk, str] = {
    LicenseRisk.PUBLIC_DOMAIN: "No obligations.",
    LicenseRisk.PERMISSIVE: (
        "Attribution, and for Apache-2.0 the patent grant and NOTICE handling."
    ),
    LicenseRisk.WEAK_COPYLEFT: (
        "Modifications to the licensed files must be published. Usually satisfied "
        "by dynamic linking and publishing patches, but check how it is linked."
    ),
    LicenseRisk.STRONG_COPYLEFT: (
        "A derivative work distributed to others must be released under the same "
        "terms. Distribution is the trigger; internal use is not."
    ),
    LicenseRisk.NETWORK_COPYLEFT: (
        "Providing the software over a network counts as distribution, so a hosted "
        "service must offer its corresponding source. This is the case a SaaS team "
        "most often does not expect."
    ),
    LicenseRisk.PROPRIETARY_OR_UNKNOWN: (
        "Unknown. A missing or unrecognised licence is not permission — it is the "
        "absence of a grant, and needs a human to read the actual terms."
    ),
}


def classify(expression: str | None) -> LicenseRisk:
    """Classify an SPDX expression by its most restrictive component.

    A compound expression is handled the honest way round: `MIT OR GPL-3.0` is
    reported at the GPL level even though the `OR` means a permissive choice is
    available. Taking the looser reading would mean the finding depends on a
    choice nobody has recorded making.
    """
    if not expression or not expression.strip():
        return LicenseRisk.PROPRIETARY_OR_UNKNOWN

    order = [
        LicenseRisk.PUBLIC_DOMAIN,
        LicenseRisk.PERMISSIVE,
        LicenseRisk.WEAK_COPYLEFT,
        LicenseRisk.STRONG_COPYLEFT,
        LicenseRisk.NETWORK_COPYLEFT,
        LicenseRisk.PROPRIETARY_OR_UNKNOWN,
    ]
    cleaned = _NOISE.sub(" ", expression.strip()).strip("()")
    parts = re.split(r"\s+(?:or|and|with)\s+|\s*[,/]\s*", cleaned, flags=re.IGNORECASE)

    worst = LicenseRisk.PUBLIC_DOMAIN
    saw_any = False
    for part in parts:
        token = _SUFFIX.sub("", part.strip().lower().strip("()+"))
        if not token:
            continue
        saw_any = True
        risk = _BY_ID.get(token, LicenseRisk.PROPRIETARY_OR_UNKNOWN)
        if order.index(risk) > order.index(worst):
            worst = risk
    return worst if saw_any else LicenseRisk.PROPRIETARY_OR_UNKNOWN


#: Trove classifier text -> SPDX identifier. Needed because a large share of
#: published packages still carry only `License :: OSI Approved :: BSD License`,
#: which is not an SPDX identifier and would otherwise classify as unknown —
#: turning the engine's output into one giant "unknown" bucket that tells a
#: reader nothing.
#:
#: The mappings that lose precision are deliberate and erring the safe way:
#: "BSD License" could be 2-clause or 3-clause and both are permissive, so
#: either answer gives the same risk band. Where a classifier spans bands —
#: "GNU General Public License (GPL)" without a version — the stricter band is
#: taken.
CLASSIFIER_TO_SPDX: dict[str, str] = {
    "mit license": "MIT",
    "mit no attribution license (mit-0)": "MIT-0",
    "apache software license": "Apache-2.0",
    "bsd license": "BSD-3-Clause",
    "isc license (iscl)": "ISC",
    "python software foundation license": "PSF-2.0",
    "zlib/libpng license": "Zlib",
    "the unlicense (unlicense)": "Unlicense",
    "cc0 1.0 universal (cc0 1.0) public domain dedication": "CC0-1.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "eclipse public license 2.0 (epl-2.0)": "EPL-2.0",
    "common development and distribution license 1.0 (cddl-1.0)": "CDDL-1.0",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.1",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.1",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0",
    "gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0",
    "gnu library or lesser general public license (lgpl)": "LGPL-3.0",
    "gnu general public license v2 (gplv2)": "GPL-2.0",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0",
    "gnu general public license v3 (gplv3)": "GPL-3.0",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0",
    "gnu general public license (gpl)": "GPL-3.0",
    "gnu affero general public license v3": "AGPL-3.0",
    "gnu affero general public license v3 or later (agpl3+)": "AGPL-3.0",
}


def from_classifier(classifier: str) -> str | None:
    """SPDX identifier for a Trove `License ::` classifier, if known.

    Takes the text after the last `::`, so both
    `License :: OSI Approved :: MIT License` and `License :: MIT License` work.
    """
    tail = classifier.split("::")[-1].strip().lower()
    return CLASSIFIER_TO_SPDX.get(tail)
