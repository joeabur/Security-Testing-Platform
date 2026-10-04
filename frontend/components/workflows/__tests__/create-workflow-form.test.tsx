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

import { CreateWorkflowForm } from "@/components/workflows/create-workflow-form";
import type { Target } from "@/lib/types";

const target: Target = {
  id: "target-1",
  organization_id: "org-1",
  name: "Acme API",
  environment: "staging",
  kind: "api",
  base_url: "https://acme.example.test",
  adapter_kind: null,
  adapter_config: {},
  code_repo_ref: null,
  runtime_protection: [],
  code_languages: [],
  code_build_manifest_paths: [],
  declared_tools: [],
  has_authorization: true,
  has_rules_of_engagement: true,
  created_at: "2026-01-01T00:00:00Z",
};

describe("CreateWorkflowForm", () => {
  beforeEach(() => {
    refreshMock.mockReset();
    fetchMock.mockReset();
  });

  it("does not show a schedule-interval field for a manual trigger", () => {
    render(<CreateWorkflowForm organizationId="org-1" targets={[target]} />);
    expect(screen.queryByLabelText(/run every/i)).not.toBeInTheDocument();
  });

  it("sends schedule_interval_minutes: null when the schedule field is left blank", async () => {
    fetchMock.mockResolvedValueOnce({ id: "wf-1" });
    render(<CreateWorkflowForm organizationId="org-1" targets={[target]} />);

    fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "Nightly gate" } });
    fireEvent.change(screen.getByLabelText(/^trigger$/i), { target: { value: "schedule" } });
    expect(screen.getByLabelText(/run every/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /create workflow/i }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.schedule_interval_minutes).toBeNull();
  });

  it("sends the chosen interval as a number when set", async () => {
    fetchMock.mockResolvedValueOnce({ id: "wf-1" });
    render(<CreateWorkflowForm organizationId="org-1" targets={[target]} />);

    fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "Nightly gate" } });
    fireEvent.change(screen.getByLabelText(/^trigger$/i), { target: { value: "schedule" } });
    fireEvent.change(screen.getByLabelText(/run every/i), { target: { value: "120" } });
    fireEvent.click(screen.getByRole("button", { name: /create workflow/i }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.schedule_interval_minutes).toBe(120);
    expect(refreshMock).toHaveBeenCalled();
  });

  it("rejects an interval below the 60-minute floor", async () => {
    render(<CreateWorkflowForm organizationId="org-1" targets={[target]} />);

    fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "Nightly gate" } });
    fireEvent.change(screen.getByLabelText(/^trigger$/i), { target: { value: "schedule" } });
    fireEvent.change(screen.getByLabelText(/run every/i), { target: { value: "5" } });
    fireEvent.click(screen.getByRole("button", { name: /create workflow/i }));

    await waitFor(() =>
      expect(screen.getByText(/minimum interval is 60 minutes/i)).toBeInTheDocument(),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
