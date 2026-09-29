import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CSRF_HEADER_NAME, PUBLIC_API_BASE_URL } from "@/lib/config";

function mockFetchOnce(body: unknown = {}, init: ResponseInit = { status: 200 }) {
  const fetchMock = vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      ...init,
      headers: { "Content-Type": "application/json" },
    }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("clientApiFetch CSRF header attachment", () => {
  beforeEach(() => {
    document.cookie = "kervy_csrf=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/";
    document.cookie = "kervy_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/";
    document.cookie = "kervy_csrf_anon=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("attaches X-CSRF-Token on an unsafe method when the CSRF cookie is present", async () => {
    document.cookie = "kervy_csrf=signed-token-value";
    const fetchMock = mockFetchOnce({ id: "org-1" });

    const { clientApiFetch } = await import("@/lib/api-client");
    await clientApiFetch("/organizations", { method: "POST", body: JSON.stringify({ name: "x" }) });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${PUBLIC_API_BASE_URL}/organizations`);
    const headers = init.headers as Headers;
    expect(headers.get(CSRF_HEADER_NAME)).toBe("signed-token-value");
  });

  it("does not attach a CSRF header for safe methods, even with the cookie present", async () => {
    document.cookie = "kervy_csrf=signed-token-value";
    const fetchMock = mockFetchOnce({ id: "org-1" });

    const { clientApiFetch } = await import("@/lib/api-client");
    await clientApiFetch("/organizations");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.has(CSRF_HEADER_NAME)).toBe(false);
  });

  it("omits the header for a session-bound path when there is no session-bound cookie yet", async () => {
    const fetchMock = mockFetchOnce({ ok: true });

    const { clientApiFetch } = await import("@/lib/api-client");
    await clientApiFetch("/organizations", { method: "POST", body: JSON.stringify({}) });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.has(CSRF_HEADER_NAME)).toBe(false);
  });

  it("fetches an anonymous CSRF token before an unsafe request to /auth/login", async () => {
    const fetchMock = vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith("/auth/csrf")) {
        // Simulates the browser applying the real Set-Cookie response header,
        // which this stub (unlike a real fetch) does not do on its own.
        document.cookie = "kervy_csrf_anon=anon-token-value";
        return new Response(null, { status: 204 });
      }
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const { clientApiFetch } = await import("@/lib/api-client");
    await clientApiFetch("/auth/login", { method: "POST", body: JSON.stringify({}) });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [firstUrl] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(firstUrl).toBe(`${PUBLIC_API_BASE_URL}/auth/csrf`);
    const [, loginInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    const headers = loginInit.headers as Headers;
    expect(headers.get(CSRF_HEADER_NAME)).toBe("anon-token-value");
  });

  it("does not re-fetch the anonymous token when the cookie is already present", async () => {
    document.cookie = "kervy_csrf_anon=already-have-one";
    const fetchMock = mockFetchOnce({ ok: true });

    const { clientApiFetch } = await import("@/lib/api-client");
    await clientApiFetch("/auth/register", { method: "POST", body: JSON.stringify({}) });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.get(CSRF_HEADER_NAME)).toBe("already-have-one");
  });

  it("does not override a caller-supplied CSRF header", async () => {
    document.cookie = "kervy_csrf=signed-token-value";
    const fetchMock = mockFetchOnce({ id: "org-1" });

    const { clientApiFetch } = await import("@/lib/api-client");
    await clientApiFetch("/organizations", {
      method: "POST",
      headers: { [CSRF_HEADER_NAME]: "caller-supplied" },
      body: JSON.stringify({ name: "x" }),
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.get(CSRF_HEADER_NAME)).toBe("caller-supplied");
  });
});
