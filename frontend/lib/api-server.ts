import "server-only";

import { cookies } from "next/headers";

import {
  CSRF_COOKIE_NAME,
  CSRF_HEADER_NAME,
  SERVER_API_BASE_URL,
  SESSION_COOKIE_NAME,
} from "./config";
import { ApiError } from "./errors";
import type { ApiErrorBody } from "./types";

// Kept in sync with `SAFE_METHODS` in app/core/csrf/enforce.py — see
// lib/api-client.ts's identical set for why this exists at all.
const CSRF_SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);

/**
 * Server-side fetch helper for Server Components and Route Handlers.
 *
 * This forwards the caller's session cookie to the backend explicitly
 * (server-side `fetch` does not do this automatically) — the backend is the
 * only thing that ever decides whether the caller is authenticated or
 * authorized, per docs/BUILD_SPEC.md §17.2: "the frontend's role-based UI
 * hiding is cosmetic only."
 *
 * It forwards the CSRF cookie the same way, for any unsafe method, even
 * though nothing calling this today performs one — the two current callers
 * are both GETs. Left unhandled, the first server-side mutation added later
 * would silently 403 against the backend's CSRF middleware exactly as the
 * client-side helper's equivalent gap did before this fix, and there would
 * be nothing here to make that failure obvious in advance.
 */
export async function serverApiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get(SESSION_COOKIE_NAME);

  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (sessionCookie) {
    headers.set("Cookie", `${SESSION_COOKIE_NAME}=${sessionCookie.value}`);
  }

  // The backend's verification (app/core/csrf/enforce.py::check) recomputes
  // the expected signature from the *session* cookie alone and compares it
  // against whatever arrives in this header — it never looks up the
  // `kervy_csrf` cookie by name. So only the header needs forwarding here;
  // the cookie's sole job was getting a same-origin-readable copy of the
  // value in front of whichever script needs to echo it, which already
  // happened when it was issued to this same server-rendered request's
  // cookie jar.
  const method = (init.method ?? "GET").toUpperCase();
  if (!CSRF_SAFE_METHODS.has(method) && !headers.has(CSRF_HEADER_NAME)) {
    const csrfCookie = cookieStore.get(CSRF_COOKIE_NAME);
    if (csrfCookie) {
      headers.set(CSRF_HEADER_NAME, csrfCookie.value);
    }
  }

  const response = await fetch(`${SERVER_API_BASE_URL}${path}`, {
    ...init,
    headers,
    cache: "no-store",
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

export async function isAuthenticated(): Promise<boolean> {
  const cookieStore = await cookies();
  return cookieStore.has(SESSION_COOKIE_NAME);
}
