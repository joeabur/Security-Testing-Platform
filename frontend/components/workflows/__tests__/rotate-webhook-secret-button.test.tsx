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

import { RotateWebhookSecretButton } from "@/components/workflows/rotate-webhook-secret-button";

describe("RotateWebhookSecretButton", () => {
  beforeEach(() => {
    refreshMock.mockReset();
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("asks for confirmation and makes no request when declined", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    render(
      <RotateWebhookSecretButton
        organizationId="org-1"
        workflowId="wf-1"
        workflowName="Staging gate"
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /rotate webhook secret/i }));

    expect(window.confirm).toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rotates and reveals the secret exactly once when confirmed", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    fetchMock.mockResolvedValueOnce({
      secret: "whsec_abc123", // pragma: allowlist secret
      webhook_url: "https://api.example.com/api/v1/webhooks/workflows/wf-1",
    });
    render(
      <RotateWebhookSecretButton
        organizationId="org-1"
        workflowId="wf-1"
        workflowName="Staging gate"
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /rotate webhook secret/i }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/organizations/org-1/workflows/wf-1/webhook-secret", {
        method: "POST",
        body: JSON.stringify({}),
      }),
    );
    expect(await screen.findByText("whsec_abc123")).toBeInTheDocument();
    expect(screen.getByText(/will not be shown again/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^done$/i }));
    expect(refreshMock).toHaveBeenCalled();
    expect(screen.queryByText("whsec_abc123")).not.toBeInTheDocument();
  });
});
