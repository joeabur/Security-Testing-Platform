import type { Metadata } from "next";

import { RunDetail } from "@/components/runs/run-detail";
import { serverApiFetch } from "@/lib/api-server";
import type { Run } from "@/lib/types";

export const metadata: Metadata = { title: "Run — Aegis AI Security" };

export default async function RunDetailPage({
  params,
}: {
  params: Promise<{ id: string; runId: string }>;
}) {
  const { id, runId } = await params;
  const run = await serverApiFetch<Run>(`/organizations/${id}/runs/${runId}`);

  return <RunDetail organizationId={id} runId={runId} initialRun={run} />;
}
