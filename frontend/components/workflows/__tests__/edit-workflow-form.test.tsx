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

import { EditWorkflowForm } from "@/components/workflows/edit-workflow-form";
import type { Workflow } from "@/lib/types";

const workflow: Workflow = {
  id: "wf-1",
  organization_id: "org-1",
  target_id: "target-1",
  name: "Staging gate",
  trigger_kind: "manual",
  enabled: true,
  gate_config: null,
  schedule_interval_minutes: null,
  next_run_at: null,
  webhook_enabled: false,
  created_at: "2026-01-01T00:00:00Z",
};

describe("EditWorkflowForm", () => {
  beforeEach(() => {
    refreshMock.mockReset();
    fetchMock.mockReset();
  });

  it("starts collapsed, showing only Edit and Delete", () => {
    render(<EditWorkflowForm organizationId="org-1" workflow={workflow} />);
    expect(screen.getByRole("button", { name: /^edit$/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^delete$/i })).toBeInTheDocument();
    expect(screen.queryByLabelText(/^name$/i)).not.toBeInTheDocument();
  });

  it("sends a PATCH with a cleared schedule when the field is left blank", async () => {
    fetchMock.mockResolvedValueOnce({ ...workflow });
    render(<EditWorkflowForm organizationId="org-1" workflow={workflow} />);

    fireEvent.click(screen.getByRole("button", { name: /^edit$/i }));
    fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "Renamed gate" } });
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe("/organizations/org-1/workflows/wf-1");
    expect(init.method).toBe("PATCH");
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({ name: "Renamed gate", enabled: true, schedule_interval_minutes: null });
    expect(refreshMock).toHaveBeenCalled();
  });

  it("deletes immediately on click, with no confirmation dialog", async () => {
    fetchMock.mockResolvedValueOnce(undefined);
    render(<EditWorkflowForm organizationId="org-1" workflow={workflow} />);

    fireEvent.click(screen.getByRole("button", { name: /^delete$/i }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/organizations/org-1/workflows/wf-1", {
        method: "DELETE",
      }),
    );
    expect(refreshMock).toHaveBeenCalled();
  });
});
