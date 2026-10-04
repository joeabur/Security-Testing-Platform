import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

const pushMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, refresh: vi.fn() }),
}));

const fetchMock = vi.fn();
vi.mock("@/lib/api-client", () => ({
  clientApiFetch: (...args: unknown[]) => fetchMock(...args),
}));

import { RetestFindingButton } from "@/components/findings/retest-finding-button";

describe("RetestFindingButton", () => {
  beforeEach(() => {
    pushMock.mockReset();
    fetchMock.mockReset();
  });

  it("disables the retest button until the authorization checkbox is confirmed", () => {
    render(
      <RetestFindingButton organizationId="org-1" findingId="finding-1" targetId="target-1" />,
    );
    expect(screen.getByRole("button", { name: /retest this finding/i })).toBeDisabled();
  });

  it("sends authorization_confirmed: true only once the checkbox is checked", async () => {
    fetchMock.mockResolvedValueOnce({ id: "run-1" });
    render(
      <RetestFindingButton organizationId="org-1" findingId="finding-1" targetId="target-1" />,
    );

    fireEvent.click(screen.getByLabelText(/i confirm this retest is authorized/i));
    const button = screen.getByRole("button", { name: /retest this finding/i });
    expect(button).toBeEnabled();
    fireEvent.click(button);

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/organizations/org-1/retests");
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({
      target_id: "target-1",
      finding_ids: ["finding-1"],
      authorization_confirmed: true,
    });
    await waitFor(() => expect(pushMock).toHaveBeenCalledWith("/organizations/org-1/runs/run-1"));
  });
});
