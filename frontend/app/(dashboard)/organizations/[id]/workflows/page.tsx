import type { Metadata } from "next";
import { Workflow as WorkflowIcon } from "lucide-react";

import { CreateWorkflowForm } from "@/components/workflows/create-workflow-form";
import { RunWorkflowButton } from "@/components/workflows/run-workflow-button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Target, Workflow } from "@/lib/types";

export const metadata: Metadata = { title: "Workflows — Kervy Security" };

export default async function WorkflowsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [workflows, targets] = await Promise.all([
    serverApiFetch<Workflow[]>(`/organizations/${id}/workflows`),
    serverApiFetch<Target[]>(`/organizations/${id}/targets`),
  ]);
  const targetNames = new Map(targets.map((target) => [target.id, target.name]));

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
                  <div className="mt-2">
                    <Badge tone={workflow.enabled ? "success" : "neutral"} dot>
                      {workflow.enabled ? "Enabled" : "Disabled"}
                    </Badge>
                  </div>
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
