"""The GitHub REST calls this platform makes, and only those.

Three of them: read a pull request's changed files, create a check run, post a
review comment. There is no method here that merges, pushes, updates a
reference or writes a file, and the egress context refuses the HTTP verbs those
would need — so the boundary is enforced by the scope engine rather than by
this module remembering.

Every request goes through `GatedTransport`. Nothing here constructs an HTTP
client, and `tests/security/test_scope_controls.py` keeps it that way.

The token travels in an `Authorization` header and nowhere else: not in a URL,
not in a log line, and not in an error string — `scrub` runs over every detail
this module returns.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from app.core.integrations.dispatch import scrub
from app.core.scope.transport import GatedTransport, ScopeBlockedError
from app.core.vcs.contract import (
    CheckRunRequest,
    Destination,
    DiffFile,
    PostOutcome,
    PullRequestRef,
    RepoRef,
    VcsError,
)
from app.core.vcs.egress import vcs_egress_context

API_VERSION = "2022-11-28"
PER_PAGE = 100
#: Bounded so a paging bug cannot walk a repository forever. A pull request
#: with more than 3000 changed files is not one anybody reviews inline anyway.
MAX_FILE_PAGES = 30

#: `@@ -12,7 +34,9 @@` — the `+34,9` says the new file's hunk starts at line 34
#: and runs for 9 lines. That is what decides where an annotation may go.
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")


def changed_lines(patch: str | None) -> frozenset[int]:
    """Line numbers in the *new* file that this patch adds or changes.

    Context and deleted lines are excluded: GitHub rejects an annotation on a
    line the diff did not add, so counting them would produce annotations that
    silently vanish — the failure `render.py` exists to avoid.
    """
    if not patch:
        return frozenset()
    lines: set[int] = set()
    cursor = 0
    for raw in patch.splitlines():
        header = _HUNK.match(raw)
        if header is not None:
            cursor = int(header.group("start"))
            continue
        if cursor == 0:
            continue
        if raw.startswith("+"):
            lines.add(cursor)
            cursor += 1
        elif raw.startswith("-"):
            # A removed line does not advance the new file's cursor.
            continue
        elif raw.startswith("\\"):
            # "\ No newline at end of file" — metadata, not a line.
            continue
        else:
            cursor += 1
    return frozenset(lines)


class GitHubClient:
    """A thin, deliberately small client over the gated transport."""

    def __init__(
        self, destination: Destination, *, transport: GatedTransport | None = None
    ) -> None:
        self._destination = destination
        self._transport = transport or GatedTransport()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._destination.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "kervy-security",
        }

    async def _request(
        self,
        ctx: Any,
        *,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
    ) -> tuple[int, Any]:
        url = f"{self._destination.api_base}{path}"
        content = json.dumps(body).encode("utf-8") if body is not None else None
        headers = self._headers()
        if content is not None:
            headers["Content-Type"] = "application/json"
        try:
            observation = await self._transport.send(
                ctx, method=method, url=url, headers=headers, content=content, timeout_seconds=20.0
            )
        except ScopeBlockedError as exc:
            raise VcsError(f"refused by scope engine: {exc.decision.reason}") from exc
        except Exception as exc:  # noqa: BLE001 - surfaced as a VcsError, scrubbed
            raise VcsError(scrub(f"{type(exc).__name__}: {exc}")) from exc

        if observation.status_code >= 400:
            # The body is not included: a GitHub error page is noise, and an
            # API that echoed our request back would put the token in it.
            raise VcsError(
                f"{method} {path} returned HTTP {observation.status_code}"
                + (
                    " — the token is missing a scope, or the app is not installed "
                    "on this repository"
                    if observation.status_code in (401, 403, 404)
                    else ""
                )
            )
        if not observation.body:
            return observation.status_code, None
        try:
            return observation.status_code, json.loads(observation.body)
        except json.JSONDecodeError as exc:
            raise VcsError(f"{method} {path} returned a body that is not JSON") from exc

    async def pull_request_files(self, ctx: Any, pull: PullRequestRef) -> list[DiffFile]:
        """The diff's files and their addable line numbers, following pages."""
        files: list[DiffFile] = []
        for page in range(1, MAX_FILE_PAGES + 1):
            _, payload = await self._request(
                ctx,
                method="GET",
                path=(
                    f"/repos/{pull.repo.owner}/{pull.repo.name}/pulls/{pull.number}/files"
                    f"?per_page={PER_PAGE}&page={page}"
                ),
            )
            if not isinstance(payload, list) or not payload:
                break
            for entry in payload:
                if not isinstance(entry, dict):
                    continue
                filename = str(entry.get("filename") or "")
                if not filename:
                    continue
                files.append(
                    DiffFile(path=filename, changed_lines=changed_lines(entry.get("patch")))
                )
            if len(payload) < PER_PAGE:
                break
        return files

    async def create_check_run(
        self, ctx: Any, repo: RepoRef, request: CheckRunRequest
    ) -> PostOutcome:
        status, payload = await self._request(
            ctx,
            method="POST",
            path=f"/repos/{repo.owner}/{repo.name}/check-runs",
            body=request.as_payload(),
        )
        body = payload if isinstance(payload, dict) else {}
        run_id = body.get("id")
        return PostOutcome(
            posted=True,
            check_run_id=int(run_id) if isinstance(run_id, int) else None,
            check_run_url=str(body.get("html_url")) if body.get("html_url") else None,
            annotations_posted=len(request.annotations),
            detail=f"check run created (HTTP {status})",
        )

    async def post_review(
        self,
        ctx: Any,
        pull: PullRequestRef,
        *,
        body: str,
        comments: Sequence[Mapping[str, Any]] = (),
    ) -> None:
        """A `COMMENT` review — never `REQUEST_CHANGES` or `APPROVE`.

        Approving is a human act and a scanner must never perform one.
        Requesting changes is left alone too: it blocks a pull request through
        the review system, where the check run is the mechanism meant for an
        automated verdict, and doing both would make the block hard to clear.
        """
        payload: dict[str, Any] = {"event": "COMMENT", "body": body}
        if comments:
            payload["comments"] = list(comments)
        await self._request(
            ctx,
            method="POST",
            path=f"/repos/{pull.repo.owner}/{pull.repo.name}/pulls/{pull.number}/reviews",
            body=payload,
        )


def context_for(destination: Destination) -> Any:
    return vcs_egress_context(destination)
