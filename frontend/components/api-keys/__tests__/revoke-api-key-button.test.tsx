import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

const refreshMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: refreshMock }),
}));

const fetchMock = vi.fn();
vi.mock("@/lib/api-client", () => ({
  clientApiFetch: (...args: unknown[]) => fetchMock(...args),
}));

import { RevokeApiKeyButton } from "@/components/api-keys/revoke-api-key-button";
import type { ApiKey } from "@/lib/types";

const apiKey: ApiKey = {
  id: "key-1",
  name: "CI pipeline",
  key_id: "kid_abc",
  scopes: ["read"],
  role: "security_engineer",
  created_at: "2026-01-01T00:00:00Z",
  expires_at: null,
  last_used_at: null,
  revoked_at: null,
};

describe("RevokeApiKeyButton", () => {
  beforeEach(() => {
    refreshMock.mockReset();
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("asks for confirmation and makes no request when declined", () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<RevokeApiKeyButton organizationId="org-1" apiKey={apiKey} />);

    fireEvent.click(screen.getByRole("button", { name: /^revoke$/i }));

    expect(window.confirm).toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("revokes when confirmed", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    fetchMock.mockResolvedValueOnce({ ...apiKey, revoked_at: "2026-01-02T00:00:00Z" });
    render(<RevokeApiKeyButton organizationId="org-1" apiKey={apiKey} />);

    fireEvent.click(screen.getByRole("button", { name: /^revoke$/i }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/organizations/org-1/api-keys/key-1/revoke", {
        method: "POST",
        body: JSON.stringify({}),
      }),
    );
    expect(refreshMock).toHaveBeenCalled();
  });

  it("shows a Revoked label instead of a button once already revoked", () => {
    render(
      <RevokeApiKeyButton
        organizationId="org-1"
        apiKey={{ ...apiKey, revoked_at: "2026-01-02T00:00:00Z" }}
      />,
    );

    expect(screen.getByText(/^revoked$/i)).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
