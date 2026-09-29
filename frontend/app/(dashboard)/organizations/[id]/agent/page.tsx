import type { Metadata } from "next";

import { AgentWorkspace } from "@/components/agent/agent-workspace";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { AgentToolCatalogEntry } from "@/lib/types";

export const metadata: Metadata = { title: "Agent — Kervy Security" };

export default async function AgentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const tools = await serverApiFetch<AgentToolCatalogEntry[]>(`/organizations/${id}/agent/tools`);

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Native AI agent</CardTitle>
          <CardDescription>
            Ask it to look something up, draft a report, or run an authorized action. It only
            uses the tools listed below — each one wraps a platform capability you could use
            directly, at the same role and authorization checks. Nothing you type here is stored:
            this transcript lives only in your browser tab and is gone on reload.
          </CardDescription>
        </CardHeader>
      </Card>

      <AgentWorkspace organizationId={id} tools={tools} />
    </div>
  );
}
