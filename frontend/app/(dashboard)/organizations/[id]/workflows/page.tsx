import type { Metadata } from "next";
import Link from "next/link";
import { Workflow as WorkflowIcon } from "lucide-react";

import { CreateWorkflowForm } from "@/components/workflows/create-workflow-form";
import { EditWorkflowForm } from "@/components/workflows/edit-workflow-form";
import { RotateWebhookSecretButton } from "@/components/workflows/rotate-webhook-secret-button";
import { RunWorkflowButton } from "@/components/workflows/run-workflow-button";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import { ApiError } from "@/lib/errors";
import { atLeast } from "@/lib/roles";
import type { Organization, Target, Workflow } from "@/lib/types";

export const metadata: Metadata = { title: "Workflows — Kervy Security" };

export default async function WorkflowsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // Listing workflows needs Analyst or higher; reading targets only needs
  // Viewer. A Viewer visiting this page is expected, not an error, so the
  // 403 is caught here rather than left to crash the page — the backend's
  // role check is still what actually decides access (per §17.2, the
  // frontend's own gating is cosmetic only); this just keeps the expected
  // "you don't have access" case from reading as a broken page.
  const [organization, targets] = await Promise.all([
    serverApiFetch<Organization>(`/organizations/${id}`),
    serverApiFetch<Target[]>(`/organizations/${id}/targets`),
  ]);
  const canManageWebhooks = atLeast(organization.role, "admin");
  let workflows: Workflow[] = [];
  let accessDenied = false;
  try {
    workflows = await serverApiFetch<Workflow[]>(`/organizations/${id}/workflows`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      accessDenied = true;
    } else {
      throw error;
    }
  }
  const targetNames = new Map(targets.map((target) => [target.id, target.name]));

  if (accessDenied) {
    return (
      <div className="flex animate-fade-in flex-col gap-6">
        <Alert tone="warning">
          You need Analyst access or higher in this organization to view workflows.
        </Alert>
      </div>
    );
  }

  return (
    <div className="flex animate-fade-in flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Create a workflow</CardTitle>
          <CardDescription>
            Five stages — trigger, plan, actions, evidence, result — whose gate decision an AI
            recommendation cannot alter.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <CreateWorkflowForm organizationId={id} targets={targets} />
        </CardContent>
      </Card>

      <div className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">Workflows</h2>
        {workflows.length === 0 ? (
          <Card className="border-dashed shadow-none">
            <CardHeader className="items-center py-10 text-center">
              <span className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
                <WorkflowIcon className="h-6 w-6" aria-hidden />
              </span>
              <CardDescription className="mt-1">No workflows yet.</CardDescription>
            </CardHeader>
          </Card>
        ) : (
          workflows.map((workflow) => (
            <Card key={workflow.id} className="transition-shadow duration-150 hover:shadow-elevated">
              <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                <div>
                  <p className="font-medium">{workflow.name}</p>
                  <p className="text-sm text-muted-foreground">
                    {targetNames.get(workflow.target_id) ?? workflow.target_id} ·{" "}
                    {workflow.trigger_kind}
                  </p>
                  <div className="mt-2 flex items-center gap-2">
                    <Badge tone={workflow.enabled ? "success" : "neutral"} dot>
                      {workflow.enabled ? "Enabled" : "Disabled"}
                    </Badge>
                    <Badge tone={workflow.webhook_enabled ? "success" : "outline"} dot>
                      {workflow.webhook_enabled ? "Webhook enabled" : "Webhook disabled"}
                    </Badge>
                  </div>
                  <Link
                    href={`/organizations/${id}/workflows/${workflow.id}`}
                    className="mt-2 inline-block text-sm text-primary hover:underline"
                  >
                    View run history
                  </Link>
                </div>
                <div className="flex flex-wrap items-center justify-end gap-2">
                  <RunWorkflowButton organizationId={id} workflowId={workflow.id} />
                  {canManageWebhooks && (
                    <RotateWebhookSecretButton
                      organizationId={id}
                      workflowId={workflow.id}
                      workflowName={workflow.name}
                    />
                  )}
                  <EditWorkflowForm organizationId={id} workflow={workflow} />
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
