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

import { RemediationTaskForm } from "@/components/remediation/remediation-task-form";
import type { Membership, RemediationRead } from "@/lib/types";

const members: Membership[] = [
  { id: "m1", user_id: "user-1", email: "alice@example.test", full_name: "Alice", role: "analyst" },
];

describe("RemediationTaskForm", () => {
  beforeEach(() => {
    refreshMock.mockReset();
    fetchMock.mockReset();
  });

  it("submits an unassigned task as a null assignee, not an empty string", async () => {
    fetchMock.mockResolvedValueOnce({});
    render(
      <RemediationTaskForm
        organizationId="org-1"
        findingId="finding-1"
        findingTitle="SQL injection"
        members={members}
        task={null}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/organizations/org-1/findings/finding-1/remediation");
    expect(init.method).toBe("PUT");
    const body = JSON.parse(init.body as string);
    expect(body.assignee_user_id).toBeNull();
    expect(body.due_date).toBeNull();
    expect(refreshMock).toHaveBeenCalled();
  });

  it("prefills from an existing task and submits the chosen assignee", async () => {
    const task: RemediationRead = {
      id: "task-1",
      finding_id: "finding-1",
      summary: "Patch the sink",
      assignee_user_id: null,
      due_date: null,
      notes: null,
      closed_at: null,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    };
    fetchMock.mockResolvedValueOnce({});
    render(
      <RemediationTaskForm
        organizationId="org-1"
        findingId="finding-1"
        findingTitle="SQL injection"
        members={members}
        task={task}
      />,
    );

    expect(screen.getByLabelText(/summary/i)).toHaveValue("Patch the sink");

    fireEvent.change(screen.getByLabelText(/assignee/i), { target: { value: "user-1" } });
    fireEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.assignee_user_id).toBe("user-1");
  });
});
