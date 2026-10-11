"""What a code-host integration is allowed to do.

The boundary is narrow and deliberate: **read a pull request's changed lines,
post a check run, post review comments.** Nothing here pushes a commit, opens a
pull request, merges one, changes a branch, or edits a file. That is not an
oversight to be filled in later — an "autofix" that writes to a customer's
repository is out of scope for this platform (docs/roadmap.md), and the way to
keep it out is to have no code that could.

Two further properties, both the same ones the notification layer has:

* **Every request goes through the scope-gated transport**, under a context
  whose allowlist holds the one code-host API hostname and nothing else
  (`egress.py`). A code-host connection cannot become a way to reach a target.
* **The token is held by reference.** A connection row stores the *name* of an
  environment variable; the value is read at post time and never persisted,
  logged, returned by the API, or put in an error string.

What gets posted is also bounded. A review comment carries a finding's title,
severity, rationale and remediation — never an evidence bundle, never a
response body, never a code snippet that a secrets engine matched. A pull
request is one of the most public places this platform writes, so the payload
is assembled from the same small scalar set the notification renderer uses and
passes the same redactor.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum


class VcsProvider(StrEnum):
    """`GITHUB_ENTERPRISE` is separate because its host is site-specific.

    github.com's API host is known and pinned in code; a Server install's is
    not, so it needs an operator to sanction it the way a generic webhook does.
    """

    GITHUB = "github"
    GITHUB_ENTERPRISE = "github_enterprise"


class CheckConclusion(StrEnum):
    """The conclusions this platform will ever report.

    Note what is missing: `action_required`. That conclusion asks a human to
    push a button that triggers a remediation, and there is no remediation for
    it to trigger — offering it would promise something that does not exist.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    NEUTRAL = "neutral"


class VcsError(Exception):
    """The connection is misconfigured or the host refused us.

    Like `IntegrationError`, this means do not retry: the same configuration
    fails the same way.
    """


#: github.com's API host, pinned in code. A `GITHUB` connection can reach this
#: and nothing else, so an organization admin can choose *which* repository to
#: post to but not *which host* to post to.
GITHUB_API_HOST = "api.github.com"

#: Conservative caps. GitHub rejects a check-run request carrying more than 50
#: annotations, and truncates output text well before 65535 characters; going
#: over means the whole post fails, which would turn a findings report into
#: silence.
MAX_ANNOTATIONS_PER_REQUEST = 50
MAX_OUTPUT_TEXT_CHARS = 60_000
MAX_SUMMARY_CHARS = 4_000


@dataclass(frozen=True)
class RepoRef:
    """`owner/name` on a particular host."""

    owner: str
    name: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True)
class PullRequestRef:
    repo: RepoRef
    number: int
    #: The head commit the check run attaches to. Required: a check run with no
    #: SHA attaches to nothing, and guessing the head would risk annotating a
    #: commit the author has already replaced.
    head_sha: str


@dataclass(frozen=True)
class Annotation:
    """One finding, anchored to a line in the diff.

    `path` is repository-relative and `start_line` is a line **in the pull
    request's diff** — GitHub silently drops an annotation outside it, so
    `render.py` filters rather than letting findings disappear without a word.
    """

    path: str
    start_line: int
    end_line: int
    level: str  # notice | warning | failure
    title: str
    message: str

    def as_payload(self) -> dict[str, object]:
        return {
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "annotation_level": self.level,
            "title": self.title[:255],
            "message": self.message[:64_000],
        }


@dataclass(frozen=True)
class CheckRunRequest:
    """A complete check run, ready to post."""

    name: str
    head_sha: str
    conclusion: CheckConclusion
    title: str
    summary: str
    text: str = ""
    annotations: Sequence[Annotation] = ()
    details_url: str | None = None

    def as_payload(self) -> dict[str, object]:
        output: dict[str, object] = {
            "title": self.title[:255],
            "summary": self.summary[:MAX_SUMMARY_CHARS],
        }
        if self.text:
            output["text"] = self.text[:MAX_OUTPUT_TEXT_CHARS]
        if self.annotations:
            output["annotations"] = [
                annotation.as_payload()
                for annotation in self.annotations[:MAX_ANNOTATIONS_PER_REQUEST]
            ]
        payload: dict[str, object] = {
            "name": self.name,
            "head_sha": self.head_sha,
            "status": "completed",
            "conclusion": self.conclusion.value,
            "output": output,
        }
        if self.details_url:
            payload["details_url"] = self.details_url
        return payload

    def as_update_payload(self) -> dict[str, object]:
        """The same check run, for `PATCH .../check-runs/{id}` rather than
        `POST .../check-runs` — everything `as_payload()` sends **except
        `output.annotations`**.

        That omission is deliberate, not an oversight: GitHub's own update
        endpoint's exact behaviour when annotations are sent again — replace
        the existing set, or add to it — was not something this change could
        verify against a real repository before shipping, and the two
        readings fail in different, both-bad ways: replace would silently
        drop annotations GitHub already has if a later update sent fewer, and
        accumulate would duplicate every annotation on every re-publish for
        the same commit. Omitting the field sidesteps the question entirely
        — whichever behaviour is real, a field that is not present is not
        acted on. The conclusion, summary and title still update correctly;
        only the annotation set does not change on a re-publish, a stated
        and deliberate narrower scope rather than a guess either way.
        """
        payload = self.as_payload()
        output = payload.get("output")
        if isinstance(output, dict):
            output.pop("annotations", None)
        return payload


@dataclass(frozen=True)
class PostOutcome:
    """What happened, in a form safe to store and return."""

    posted: bool
    check_run_id: int | None = None
    check_run_url: str | None = None
    annotations_posted: int = 0
    annotations_dropped: int = 0
    #: Already scrubbed. Never a token, never a response body.
    detail: str = ""


@dataclass(frozen=True)
class Destination:
    """A resolved code-host endpoint, after policy checks."""

    provider: VcsProvider
    host: str
    api_base: str
    token: str = field(repr=False, default="")

    def __post_init__(self) -> None:
        if not self.host:
            raise VcsError("code host connection has no host")


@dataclass(frozen=True)
class DiffFile:
    """A file in a pull request's diff, and which of its lines are addable.

    GitHub accepts an annotation only on a line the diff touches. Rather than
    post annotations and let the host discard them silently, the changed line
    numbers are read first and `render.py` filters against them — a finding
    that cannot be annotated goes into the summary instead, where it is still
    visible.
    """

    path: str
    changed_lines: frozenset[int]

    def covers(self, line: int | None) -> bool:
        return line is not None and line in self.changed_lines


def diff_index(files: Sequence[DiffFile]) -> Mapping[str, DiffFile]:
    return {item.path: item for item in files}
