"""What a DAST run is, and what it is allowed to do.

DAST is the first engine in this platform that **discovers its own targets**.
Every other engine works from something a human supplied: an OpenAPI document, a
declared adapter, a checkout path. A crawler follows links, which means the set
of URLs it might request is decided by the application under test rather than by
the operator.

That inverts the usual trust relationship, so the contract is written around it:

* **A discovered URL is checked before it is queued**, not before it is fetched.
  See `crawl.py`.
* **A crawl is bounded in every dimension**: total pages, depth, per-page links,
  response size, and the run's own request budget. An application that generates
  infinite links — a calendar, a faceted search — must exhaust a bound rather
  than the operator's patience.
* **State-changing requests need `allow_state_mutation`.** Under the default the
  crawler issues `GET` only and never submits a form, because "crawl the site"
  should not mean "click every delete button".
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CrawlOutcome(StrEnum):
    """Why a crawl stopped. All of these are normal endings, not errors.

    Reported in the findings so a reader knows whether coverage was complete or
    merely bounded — a crawl that stopped at `PAGE_LIMIT` has said nothing about
    the pages it never reached.
    """

    EXHAUSTED = "exhausted"
    PAGE_LIMIT = "page_limit"
    DEPTH_LIMIT = "depth_limit"
    BUDGET_EXHAUSTED = "budget_exhausted"
    HALTED = "halted"


#: Conservative bounds. A crawl is reconnaissance for the probes that follow,
#: not an attempt to enumerate an entire site.
DEFAULT_MAX_PAGES = 200
DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_LINKS_PER_PAGE = 100
#: 2 MiB. Larger responses are fetched but only this much is parsed for links —
#: a 200 MB file should not become 200 MB of parser input.
DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024

#: Extensions that never contain links worth following, and whose bodies are
#: large. Skipped at queue time so they do not consume page budget.
SKIP_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".bmp",
        ".tiff",
        ".css",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".webm",
        ".ogg",
        ".wav",
        ".exe",
        ".dmg",
        ".iso",
        ".bin",
    }
)


@dataclass(frozen=True)
class CrawlLimits:
    max_pages: int = DEFAULT_MAX_PAGES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_links_per_page: int = DEFAULT_MAX_LINKS_PER_PAGE
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES

    def __post_init__(self) -> None:
        for name in ("max_pages", "max_depth", "max_links_per_page", "max_body_bytes"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")


@dataclass(frozen=True)
class RefusedUrl:
    """A discovered URL the scope engine would not permit.

    Recorded rather than dropped, because "the application links to somewhere we
    are not authorized to touch" is worth a human's attention — it is how you
    find out a site embeds a third-party tracker, or that the authorization
    covers less than the application spans. The **reason** is the engine's own
    rule name, so the record cannot drift from the decision.
    """

    url: str
    rule: str
    reason: str
    #: The page it was found on, so a reader can go and look.
    discovered_on: str


@dataclass(frozen=True)
class CrawledPage:
    url: str
    status_code: int
    content_type: str
    depth: int
    #: In-scope links found here, already normalized and de-duplicated.
    links: tuple[str, ...] = ()
    #: Form actions found here. Recorded even under the default, because the
    #: *existence* of a state-changing form is useful to a reviewer; only
    #: submitting one requires `allow_state_mutation`.
    forms: tuple[str, ...] = ()
    title: str = ""


@dataclass
class CrawlResult:
    """Everything a crawl learned, including what it refused to touch."""

    seed: str
    pages: list[CrawledPage] = field(default_factory=list)
    refused: list[RefusedUrl] = field(default_factory=list)
    outcome: CrawlOutcome = CrawlOutcome.EXHAUSTED
    #: URLs that were in scope and queued but never fetched, because a bound was
    #: reached first. Named so coverage is not overstated.
    unvisited: list[str] = field(default_factory=list)

    @property
    def urls(self) -> tuple[str, ...]:
        return tuple(page.url for page in self.pages)

    def complete(self) -> bool:
        return self.outcome is CrawlOutcome.EXHAUSTED and not self.unvisited


@dataclass(frozen=True)
class DastTarget:
    """The input to the DAST engine.

    `allow_state_mutation` is carried explicitly rather than read from the RoE
    inside each adapter, so there is one place it is resolved and every adapter
    sees the same answer.
    """

    seed_url: str
    allow_state_mutation: bool = False
    limits: CrawlLimits = field(default_factory=CrawlLimits)
    #: Extra URLs the operator supplied — a login page, a deep link the crawler
    #: would not reach. Checked exactly like a discovered one.
    extra_seeds: Sequence[str] = ()
    #: Opt in to a real-browser crawl (`browser.py`) instead of the regex-based
    #: one above. Off by default, the same secure-default idiom
    #: `allow_state_mutation` uses: a browser engine is a materially larger
    #: thing to run against a live target, so it is never silently substituted.
    use_browser: bool = False
    #: A Playwright storage state (cookies/localStorage) the operator already
    #: captured from an authenticated session, carried through every
    #: navigation. The whole of this engine's "authenticated session" support
    #: — it does not drive a login form itself (`browser.py`'s docstring
    #: explains why). Ignored unless `use_browser` is set.
    storage_state: Mapping[str, Any] | None = None
