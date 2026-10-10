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

import { ApproveRejectRunButtons } from "@/components/workflows/approve-reject-run-buttons";
import type { WorkflowRun } from "@/lib/types";

const run: WorkflowRun = {
  id: "run-1",
  workflow_id: "wf-1",
  assessment_run_id: null,
  status: "awaiting_approval",
  trigger: {},
  plan: {},
  plan_digest: "digest",
  stages: [],
  evidence_refs: [],
  gate_passed: null,
  gate_exit_code: null,
  gate_reasons: [],
  gate_counts: {},
  started_at: null,
  finished_at: null,
  detail: null,
  approved_by_user_id: null,
  approved_at: null,
  created_at: "2026-01-01T00:00:00Z",
};

describe("ApproveRejectRunButtons", () => {
  beforeEach(() => {
    refreshMock.mockReset();
    fetchMock.mockReset();
  });

  it("approves immediately on click, with no reason required", async () => {
    fetchMock.mockResolvedValueOnce({ ...run, status: "running" });
    render(<ApproveRejectRunButtons organizationId="org-1" workflowId="wf-1" run={run} />);

    fireEvent.click(screen.getByRole("button", { name: /^approve$/i }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/organizations/org-1/workflows/wf-1/runs/run-1/approve", {
        method: "POST",
        body: JSON.stringify({}),
      }),
    );
    expect(refreshMock).toHaveBeenCalled();
  });

  it("blocks reject submission until a reason is typed", async () => {
    render(<ApproveRejectRunButtons organizationId="org-1" workflowId="wf-1" run={run} />);

    fireEvent.click(screen.getByRole("button", { name: /^reject$/i }));
    const confirmButton = screen.getByRole("button", { name: /confirm reject/i });
    expect(confirmButton).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/rejection reason/i), {
      target: { value: "Findings regressed since the last approved run" },
    });
    expect(confirmButton).not.toBeDisabled();

    fetchMock.mockResolvedValueOnce({ ...run, status: "refused" });
    fireEvent.click(confirmButton);

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith("/organizations/org-1/workflows/wf-1/runs/run-1/reject", {
        method: "POST",
        body: JSON.stringify({ reason: "Findings regressed since the last approved run" }),
      }),
    );
    expect(refreshMock).toHaveBeenCalled();
  });

  it("cancels back to Approve/Reject without sending a request", () => {
    render(<ApproveRejectRunButtons organizationId="org-1" workflowId="wf-1" run={run} />);

    fireEvent.click(screen.getByRole("button", { name: /^reject$/i }));
    fireEvent.click(screen.getByRole("button", { name: /^cancel$/i }));

    expect(screen.getByRole("button", { name: /^approve$/i })).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
