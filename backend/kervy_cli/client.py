"""A thin REST client, and the mapping from an API refusal to an exit code.

§20 requires distinct exit codes so CI can tell "found issues" apart from
"refused to run". That mapping lives here, in one place, so no command can
accidentally report a scope refusal as a gate failure — which would send
someone hunting for a vulnerability that does not exist.
"""

from typing import Any

import httpx

from app.core.gate.model import ExitCode


class CliError(Exception):
    """A failure with the exit code it should produce."""

    def __init__(self, message: str, exit_code: ExitCode = ExitCode.CONFIG_ERROR) -> None:
        super().__init__(message)
        self.exit_code = exit_code


# What the platform's refusals mean for a pipeline.
#
# 401/403 are an authentication or authorization problem with the *caller*:
# the credential is wrong, expired, or not privileged enough. 409 is the
# platform refusing on scope or authorization grounds — the request was
# understood and declined, which is a scope violation from CI's point of view
# and must never be reported as "no findings".
_STATUS_CODES = {
    401: ExitCode.AUTH_ERROR,
    403: ExitCode.AUTH_ERROR,
    409: ExitCode.SCOPE_VIOLATION,
}


class ApiClient:
    """The CLI's only way to reach the platform.

    Note what is absent: any import of the scope engine, a probe, an adapter
    or a database session. The CLI asks the API to act, so every request it
    causes goes through the same authorization gate a browser session does.
    """

    def __init__(self, base_url: str, token: str | None, *, timeout: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        if not self._token:
            raise CliError(
                "not authenticated: run `kervy-ai login`, or set KERVY_API_KEY",
                ExitCode.AUTH_ERROR,
            )
        return {"Authorization": f"Bearer {self._token}"}

    def fetch_anon_csrf_token(self) -> tuple[str, str]:
        """The pre-session token `/auth/login` and `/auth/register` now
        require (app/core/csrf/anon.py) — `login` has no bearer token yet to
        authenticate with, so it has to go through the same front door a
        browser does: fetch the cookie the endpoint sets, then send its value
        back as *both* the cookie and the header on the next request.

        Returns `(cookie_name, value)`: the name matters too, because the
        server chooses between `__Host-kervy_csrf_anon` and
        `kervy_csrf_anon` depending on its own `KERVY_SESSION_COOKIE_SECURE`
        setting, which this client has no independent way to know — it reads
        back whichever one the response actually set.

        A fresh `httpx.Client` per call (matching `request()` below) means
        this can't rely on a cookie jar carrying the value forward the way a
        browser's would — it is read directly off this response and threaded
        through explicitly.
        """
        url = f"{self._base_url}/auth/csrf"
        try:
            # nosemgrep: kervy.ungated-http-client
            with httpx.Client(timeout=self._timeout, follow_redirects=False) as client:
                response = client.get(url)
        except httpx.HTTPError as exc:
            raise CliError(f"could not reach {url}: {exc}", ExitCode.CONFIG_ERROR) from exc
        if response.status_code >= 400:
            raise CliError(
                f"GET /auth/csrf failed with HTTP {response.status_code}: {_message_of(response)}",
                _STATUS_CODES.get(response.status_code, ExitCode.CONFIG_ERROR),
            )
        for cookie in response.cookies.jar:
            if cookie.name in ("__Host-kervy_csrf_anon", "kervy_csrf_anon") and cookie.value:
                return cookie.name, cookie.value
        raise CliError("GET /auth/csrf did not set a CSRF cookie", ExitCode.CONFIG_ERROR)

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        params: dict[str, Any] | None = None,
        authenticated: bool = True,
        expect_json: bool = True,
        extra_headers: dict[str, str] | None = None,
        extra_cookies: dict[str, str] | None = None,
    ) -> Any:
        headers = self._headers() if authenticated else {}
        headers.update(extra_headers or {})
        url = f"{self._base_url}{path}"
        try:
            # The one client outside the scope engine, and deliberately so:
            # this talks to the Kervy API at an address the operator
            # configured, never to a target. The scope engine exists to gate
            # requests *at* a system under test, and routing an operator's
            # call to their own platform through it would be theatre. The CLI
            # has no other HTTP path — `tests/test_cli.py` asserts it cannot
            # even import the engine, so it cannot reach a target except by
            # asking the API to.
            # nosemgrep: kervy.ungated-http-client
            with httpx.Client(timeout=self._timeout, follow_redirects=False) as client:
                response = client.request(
                    method,
                    url,
                    json=json_body,
                    params=params,
                    headers=headers,
                    cookies=extra_cookies,
                )
        except httpx.HTTPError as exc:
            raise CliError(f"could not reach {url}: {exc}", ExitCode.CONFIG_ERROR) from exc

        if response.status_code >= 400:
            raise CliError(
                f"{method} {path} failed with HTTP {response.status_code}: {_message_of(response)}",
                _STATUS_CODES.get(response.status_code, ExitCode.CONFIG_ERROR),
            )

        if not expect_json:
            return response
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise CliError(
                f"{path} returned a body that is not JSON", ExitCode.CONFIG_ERROR
            ) from exc


def _message_of(response: httpx.Response) -> str:
    """The platform's structured error message, or the raw body.

    Clipped: an error body is not a place to dump a page of HTML into
    somebody's CI log.
    """
    try:
        payload = response.json()
    except ValueError:
        return response.text[:400]
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict) and error.get("message"):
            return str(error["message"])
        if payload.get("detail"):
            return str(payload["detail"])
    return str(payload)[:400]
