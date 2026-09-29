/**
 * The backend is reached by two different names depending on where the code
 * runs: server components/route handlers run inside the Docker network and
 * talk to the `backend` service directly, while the browser only ever knows
 * about the publicly exposed URL. Both must point at the same backend.
 */
export const SERVER_API_BASE_URL =
  process.env.BACKEND_INTERNAL_URL ?? "http://localhost:8000/api/v1";

export const PUBLIC_API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

// The same backend, without the `/api/v1` suffix — for linking to the
// server-rendered dashboard (`/app/...`), which lives on the backend rather
// than in this app. Its session cookie is host-scoped, not port-scoped, so a
// visitor already signed in here is already signed in there too; this is
// just the link, not a second auth flow.
export const PUBLIC_APP_BASE_URL = PUBLIC_API_BASE_URL.replace(/\/api\/v1\/?$/, "");

export const SESSION_COOKIE_NAME = "kervy_session";

// Must match app/core/csrf/enforce.py's COOKIE_NAME and HEADER_NAME exactly —
// this is the client half of the same contract, not an independent choice.
export const CSRF_COOKIE_NAME = "kervy_csrf";
export const CSRF_HEADER_NAME = "X-CSRF-Token";

// The pre-session token for /auth/login and /auth/register (see
// app/core/csrf/anon.py). Two names because `__Host-` cookies require HTTPS:
// a deployment serving over TLS gets the host-locked name, everything else
// (local dev, by default) gets the plain one. Must match
// app/core/csrf/anon.py's cookie_name() exactly.
export const CSRF_ANON_COOKIE_NAME_SECURE = "__Host-kervy_csrf_anon";
export const CSRF_ANON_COOKIE_NAME_INSECURE = "kervy_csrf_anon";

// Relative paths (as passed to clientApiFetch) that need the anonymous
// token above instead of the session-bound one, because no session exists
// yet when they're called. Must match ANONYMOUS_CSRF_PATHS in
// app/core/csrf/enforce.py (there, prefixed with /api/v1).
export const ANONYMOUS_CSRF_PATHS = new Set(["/auth/login", "/auth/register"]);
