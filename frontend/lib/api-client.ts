"use client";

import {
  ANONYMOUS_CSRF_PATHS,
  CSRF_ANON_COOKIE_NAME_INSECURE,
  CSRF_ANON_COOKIE_NAME_SECURE,
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
  PUBLIC_API_BASE_URL,
} from "./config";
import { ApiError } from "./errors";
import type { ApiErrorBody } from "./types";

/** Methods the backend's CSRF middleware treats as safe and never checks —
 * kept in sync with `SAFE_METHODS` in app/core/csrf/enforce.py. Anything else
 * sent with the session cookie needs the token attached below, or the
 * backend refuses it with 403 regardless of how valid the session is. */
const CSRF_SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);

function readCookie(name: string): string | null {
  // SSR/server components have no `document`; those calls go through
  // lib/api-server.ts's `serverApiFetch`, which forwards the CSRF cookie
  // itself rather than reading it from a DOM this context does not have —
  // so returning null here is correct, not a fallback masking a bug.
  if (typeof document === "undefined") {
    return null;
  }
  const match = document.cookie.match(
    new RegExp(`(?:^|; )${name.replace(/([.$?*|{}()[\]\\/+^])/g, "\\$1")}=([^;]*)`),
  );
  return match?.[1] !== undefined ? decodeURIComponent(match[1]) : null;
}

function readAnonCsrfCookie(): string | null {
  return readCookie(CSRF_ANON_COOKIE_NAME_SECURE) ?? readCookie(CSRF_ANON_COOKIE_NAME_INSECURE);
}

/**
 * `/auth/login` and `/auth/register` need the pre-session token from
 * `GET /auth/csrf` (see app/core/csrf/anon.py), not the session-bound one —
 * there is no session yet for that one to be bound to. Fetched lazily, only
 * when a caller is about to need it and doesn't already have it, so a page
 * that never submits either form never makes the extra round trip.
 */
async function ensureAnonCsrfToken(): Promise<string | null> {
  const existing = readAnonCsrfCookie();
  if (existing) {
    return existing;
  }
  await fetch(`${PUBLIC_API_BASE_URL}/auth/csrf`, { credentials: "include" });
  return readAnonCsrfCookie();
}

/**
 * Browser-side fetch helper. `credentials: "include"` sends the session
 * cookie the backend set on login/register.
 *
 * For any unsafe method the backend's CSRF middleware requires a matching
 * `X-CSRF-Token` header alongside that cookie (app/core/csrf/), because the
 * cookie alone is exactly what a forged cross-site request would also carry.
 * The token cookie is deliberately readable by this same-origin script (see
 * its own `httponly=False` on the backend) so it can be echoed here — an
 * attacker's page cannot read it, which is the whole point.
 *
 * A write made before any session exists — `/auth/login` and
 * `/auth/register`, per `ANONYMOUS_CSRF_PATHS` above — has no session-bound
 * cookie to read, but is not exempt either any more: it needs the separate
 * pre-session token `ensureAnonCsrfToken` fetches on demand. See
 * app/core/csrf/anon.py for why a merely self-signed token isn't enough on
 * its own and this still has to be a real cookie the browser holds.
 */
export async function clientApiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const method = (init.method ?? "GET").toUpperCase();
  if (!CSRF_SAFE_METHODS.has(method) && !headers.has(CSRF_HEADER_NAME)) {
    const token = ANONYMOUS_CSRF_PATHS.has(path)
      ? await ensureAnonCsrfToken()
      : readCookie(CSRF_COOKIE_NAME);
    if (token) {
      headers.set(CSRF_HEADER_NAME, token);
    }
  }

  const response = await fetch(`${PUBLIC_API_BASE_URL}${path}`, {
    ...init,
    headers,
    credentials: "include",
  });

  if (!response.ok) {
    const body = (await safeJson(response)) as Partial<ApiErrorBody> | null;
    throw new ApiError(response.status, body);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

async function safeJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

/**
 * Same session-cookie auth as `clientApiFetch`, but for an endpoint that
 * returns a file (`Content-Disposition: attachment`) rather than JSON — the
 * report and evidence download routes. GET is CSRF-safe, so no token header
 * is needed here either.
 */
export async function clientApiDownload(
  path: string,
): Promise<{ blob: Blob; filename: string }> {
  const response = await fetch(`${PUBLIC_API_BASE_URL}${path}`, { credentials: "include" });

  if (!response.ok) {
    const body = (await safeJson(response)) as Partial<ApiErrorBody> | null;
    throw new ApiError(response.status, body);
  }

  const disposition = response.headers.get("Content-Disposition") ?? "";
  const match = disposition.match(/filename="([^"]+)"/);
  const filename = match?.[1] ?? "download";

  return { blob: await response.blob(), filename };
}
