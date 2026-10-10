import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

import { ApproveRejectRunButtons } from "@/components/workflows/approve-reject-run-buttons";
import { Alert } from "@/components/ui/alert";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import { ApiError } from "@/lib/errors";
import { atLeast } from "@/lib/roles";
import type { Organization, Workflow, WorkflowRun } from "@/lib/types";

export const metadata: Metadata = { title: "Workflow runs — Kervy Security" };

const STATUS_TONE: Record<string, BadgeProps["tone"]> = {
  completed: "success",
  running: "primary",
  pending: "neutral",
  failed: "destructive",
  refused: "destructive",
  awaiting_approval: "warning",
};

export default async function WorkflowRunsPage({
  params,
}: {
  params: Promise<{ id: string; workflowId: string }>;
}) {
  const { id, workflowId } = await params;

  // Reached either from the workflows list (which already needs Analyst) or
  // by direct URL, which a Viewer can still type in — so this page needs its
  // own 403 catch independent of the list page's, per §17.2's "the frontend's
  // own gating is cosmetic" rule.
  let workflow: Workflow;
  let organization: Organization;
  try {
    [workflow, organization] = await Promise.all([
      serverApiFetch<Workflow>(`/organizations/${id}/workflows/${workflowId}`),
      serverApiFetch<Organization>(`/organizations/${id}`),
    ]);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      return (
        <div className="flex animate-fade-in flex-col gap-6">
          <Alert tone="warning">
            You need Analyst access or higher in this organization to view this workflow.
          </Alert>
        </div>
      );
    }
    throw error;
  }

  const runs = await serverApiFetch<WorkflowRun[]>(
    `/organizations/${id}/workflows/${workflowId}/runs`,
  );
  // Same tier the backend requires to approve/reject (_RUNNER =
  // Role.SECURITY_ENGINEER) — approving a paused run is authorizing a scan,
  // the same act `RunWorkflowButton`'s own trigger requires.
  const canApprove = atLeast(organization.role, "security_engineer");

  return (
    <div className="flex animate-fade-in flex-col gap-6">
      <div>
        <Link
          href={`/organizations/${id}/workflows`}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden />
          Workflows
        </Link>
        <h2 className="mt-2 text-xl font-semibold">{workflow.name} — run history</h2>
      </div>

      <div className="flex flex-col gap-3">
        {runs.length === 0 ? (
          <Card className="border-dashed shadow-none">
            <CardHeader className="items-center py-10 text-center">
              <CardDescription>No runs yet for this workflow.</CardDescription>
            </CardHeader>
          </Card>
        ) : (
          runs.map((run) => (
            <Card key={run.id}>
              <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={STATUS_TONE[run.status] ?? "neutral"} dot>
                      {run.status.replace(/_/g, " ")}
                    </Badge>
                    {run.gate_passed !== null && (
                      <Badge tone={run.gate_passed ? "success" : "destructive"}>
                        {run.gate_passed ? "Gate passed" : "Gate failed"}
                      </Badge>
                    )}
                  </div>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {new Date(run.created_at).toLocaleString()}
                  </p>
                  {run.detail && (
                    <p className="mt-1 text-sm text-muted-foreground">{run.detail}</p>
                  )}
                  {run.gate_reasons.length > 0 && (
                    <ul className="mt-1 list-inside list-disc text-xs text-muted-foreground">
                      {run.gate_reasons.map((reason) => (
                        <li key={reason}>{reason}</li>
                      ))}
                    </ul>
                  )}
                </div>
                {run.status === "awaiting_approval" && canApprove && (
                  <ApproveRejectRunButtons
                    organizationId={id}
                    workflowId={workflowId}
                    run={run}
                  />
                )}
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
