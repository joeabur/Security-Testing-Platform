import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

const fetchMock = vi.fn();
vi.mock("@/lib/api-client", () => ({
  clientApiFetch: (...args: unknown[]) => fetchMock(...args),
}));

import { AgentWorkspace } from "@/components/agent/agent-workspace";
import type { Investigation } from "@/lib/types";

const baseOutcome = {
  tool_name: "list_targets",
  status: "ok" as const,
  result: { targets: [] },
  error: null,
  duration_ms: 12,
};

// The real poll interval (agent-workspace.tsx's own POLL_MS) is 2s — these
// tests wait for the real timer to fire rather than faking it, since
// testing-library's own `waitFor` polls on the same clock and the two
// don't mix well under `vi.useFakeTimers()`.
const POLL_WAIT = { timeout: 4000 };

describe("AgentWorkspace", () => {
  beforeEach(() => {
    fetchMock.mockReset();
  });

  it(
    "keeps earlier steps on screen across a poll, instead of being wiped by the empty outcomes /status returns",
    async () => {
      const investigate: Investigation = {
        investigation_id: "inv-1",
        status: "awaiting_approval",
        outcomes: [baseOutcome],
        summary: null,
        pending_approval: {
          tool_name: "run_scan",
          risk_level: "sensitive",
          description: "Starts a live scan against a target.",
        },
      };
      fetchMock.mockResolvedValueOnce(investigate);

      render(<AgentWorkspace organizationId="org-1" tools={[]} />);
      fireEvent.change(screen.getByPlaceholderText(/list my authorized targets/i), {
        target: { value: "scan acme-api" },
      });
      fireEvent.click(screen.getByRole("button", { name: /ask the agent/i }));

      await waitFor(() => expect(screen.getByText("list_targets")).toBeInTheDocument());

      // The backend's /status endpoint always returns an empty outcomes
      // list (nothing new to report) — the poll must not use that to
      // erase the step already shown.
      const polled: Investigation = { ...investigate, outcomes: [] };
      fetchMock.mockResolvedValueOnce(polled);

      await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2), POLL_WAIT);
      expect(screen.getByText("list_targets")).toBeInTheDocument();
    },
    6000,
  );

  it("accumulates the steps run after approval onto the existing transcript", async () => {
    const investigate: Investigation = {
      investigation_id: "inv-1",
      status: "awaiting_approval",
      outcomes: [baseOutcome],
      summary: null,
      pending_approval: {
        tool_name: "run_scan",
        risk_level: "sensitive",
        description: "Starts a live scan against a target.",
      },
    };
    fetchMock.mockResolvedValueOnce(investigate);

    render(<AgentWorkspace organizationId="org-1" tools={[]} />);
    fireEvent.change(screen.getByPlaceholderText(/list my authorized targets/i), {
      target: { value: "scan acme-api" },
    });
    fireEvent.click(screen.getByRole("button", { name: /ask the agent/i }));
    await waitFor(() => expect(screen.getByText("list_targets")).toBeInTheDocument());

    const afterApprove: Investigation = {
      investigation_id: "inv-1",
      status: "completed",
      outcomes: [{ ...baseOutcome, tool_name: "run_scan" }],
      summary: "Scan completed with no new findings.",
      pending_approval: null,
    };
    fetchMock.mockResolvedValueOnce(afterApprove);

    fireEvent.click(screen.getByRole("button", { name: /^approve$/i }));

    await waitFor(() => expect(screen.getByText("run_scan")).toBeInTheDocument());
    // The step from before the approval must still be there alongside it.
    expect(screen.getByText("list_targets")).toBeInTheDocument();
    expect(screen.getByText(/scan completed with no new findings/i)).toBeInTheDocument();
  });

  it("starts a fresh transcript for a new investigation rather than merging onto the old one", async () => {
    const first: Investigation = {
      investigation_id: "inv-1",
      status: "completed",
      outcomes: [baseOutcome],
      summary: "Done.",
      pending_approval: null,
    };
    fetchMock.mockResolvedValueOnce(first);

    render(<AgentWorkspace organizationId="org-1" tools={[]} />);
    fireEvent.change(screen.getByPlaceholderText(/list my authorized targets/i), {
      target: { value: "list targets" },
    });
    fireEvent.click(screen.getByRole("button", { name: /ask the agent/i }));
    await waitFor(() => expect(screen.getByText("list_targets")).toBeInTheDocument());

    const second: Investigation = {
      investigation_id: "inv-2",
      status: "completed",
      outcomes: [{ ...baseOutcome, tool_name: "get_finding" }],
      summary: "Done again.",
      pending_approval: null,
    };
    fetchMock.mockResolvedValueOnce(second);

    fireEvent.change(screen.getByPlaceholderText(/list my authorized targets/i), {
      target: { value: "get the finding" },
    });
    fireEvent.click(screen.getByRole("button", { name: /ask the agent/i }));

    await waitFor(() => expect(screen.getByText("get_finding")).toBeInTheDocument());
    expect(screen.queryByText("list_targets")).not.toBeInTheDocument();
  });
});
