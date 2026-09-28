import type { Metadata } from "next";
import { Workflow as WorkflowIcon } from "lucide-react";

import { CreateWorkflowForm } from "@/components/workflows/create-workflow-form";
import { RunWorkflowButton } from "@/components/workflows/run-workflow-button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Target, Workflow } from "@/lib/types";

export const metadata: Metadata = { title: "Workflows — Aegis AI Security" };

export default async function WorkflowsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [workflows, targets] = await Promise.all([
    serverApiFetch<Workflow[]>(`/organizations/${id}/workflows`),
    serverApiFetch<Target[]>(`/organizations/${id}/targets`),
  ]);
  const targetNames = new Map(targets.map((target) => [target.id, target.name]));

  return (
    <div className="flex flex-col gap-6">
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
          <Card>
            <CardHeader className="items-center text-center">
              <WorkflowIcon className="h-8 w-8 text-muted-foreground" aria-hidden />
              <CardDescription>No workflows yet.</CardDescription>
            </CardHeader>
          </Card>
        ) : (
          workflows.map((workflow) => (
            <Card key={workflow.id}>
              <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                <div>
                  <p className="font-medium">{workflow.name}</p>
                  <p className="text-sm text-muted-foreground">
                    {targetNames.get(workflow.target_id) ?? workflow.target_id} ·{" "}
                    {workflow.trigger_kind} · {workflow.enabled ? "enabled" : "disabled"}
                  </p>
                </div>
                <RunWorkflowButton organizationId={id} workflowId={workflow.id} />
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
