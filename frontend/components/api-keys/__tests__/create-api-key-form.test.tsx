import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

const refreshMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: refreshMock }),
}));

const fetchMock = vi.fn();
vi.mock("@/lib/api-client", () => ({
  clientApiFetch: (...args: unknown[]) => fetchMock(...args),
}));

import { CreateApiKeyForm } from "@/components/api-keys/create-api-key-form";

describe("CreateApiKeyForm", () => {
  beforeEach(() => {
    refreshMock.mockReset();
    fetchMock.mockReset();
  });

  it("requires at least one scope before submitting", async () => {
    render(<CreateApiKeyForm organizationId="org-1" />);

    fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "CI pipeline" } });
    fireEvent.click(screen.getByRole("button", { name: /create api key/i }));

    expect(await screen.findByText(/choose at least one scope/i)).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("creates a key and reveals the token exactly once", async () => {
    fetchMock.mockResolvedValueOnce({
      id: "key-1",
      name: "CI pipeline",
      key_id: "kid_abc",
      scopes: ["read", "scan"],
      role: "security_engineer",
      created_at: "2026-01-01T00:00:00Z",
      expires_at: null,
      last_used_at: null,
      revoked_at: null,
      token: "kervy_kid_abc_secretvalue",
    });
    render(<CreateApiKeyForm organizationId="org-1" />);

    fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "CI pipeline" } });
    fireEvent.click(screen.getByLabelText(/^read/i));
    fireEvent.click(screen.getByLabelText(/^scan/i));
    fireEvent.click(screen.getByRole("button", { name: /create api key/i }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/organizations/org-1/api-keys");
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({ name: "CI pipeline", scopes: ["read", "scan"], expires_at: null });

    expect(await screen.findByText("kervy_kid_abc_secretvalue")).toBeInTheDocument();
    expect(screen.getByText(/will not be shown again/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^done$/i }));
    expect(refreshMock).toHaveBeenCalled();
  });
});
