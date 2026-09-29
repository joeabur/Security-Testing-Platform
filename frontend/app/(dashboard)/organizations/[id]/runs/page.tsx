import type { Metadata } from "next";
import Link from "next/link";
import { Activity } from "lucide-react";

import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Run, Target } from "@/lib/types";

export const metadata: Metadata = { title: "Runs — Kervy Security" };

const STATUS_TONE: Record<string, BadgeProps["tone"]> = {
  completed: "success",
  running: "primary",
  queued: "neutral",
  failed: "destructive",
  cancelled: "neutral",
  expired: "destructive",
};

export default async function RunsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [runs, targets] = await Promise.all([
    serverApiFetch<Run[]>(`/organizations/${id}/runs`),
    serverApiFetch<Target[]>(`/organizations/${id}/targets`),
  ]);
  const targetNames = new Map(targets.map((target) => [target.id, target.name]));

  return (
    <div className="flex animate-fade-in flex-col gap-3">
      <h2 className="text-lg font-semibold">Runs</h2>
      {runs.length === 0 ? (
        <Card className="border-dashed shadow-none">
          <CardHeader className="items-center py-10 text-center">
            <span className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
              <Activity className="h-6 w-6" aria-hidden />
            </span>
            <CardDescription className="mt-1">
              No runs yet. Start one from a target&apos;s page once it has Rules of Engagement
              and authorization, or scan a connected repository.
            </CardDescription>
          </CardHeader>
        </Card>
      ) : (
        runs
          .slice()
          .reverse()
          .map((run) => (
            <Link key={run.id} href={`/organizations/${id}/runs/${run.id}`}>
              <Card className="transition-all duration-150 hover:border-primary/40 hover:shadow-elevated">
                <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                  <div>
                    <p className="font-medium">{targetNames.get(run.target_id) ?? run.target_id}</p>
                    <p className="text-sm text-muted-foreground">
                      {run.profile} · {run.checks_completed}/{run.checks_total} checks ·{" "}
                      {run.findings_reported} findings
                    </p>
                  </div>
                  <Badge tone={STATUS_TONE[run.status] ?? "neutral"} dot>
                    {run.status}
                  </Badge>
                </CardContent>
              </Card>
            </Link>
          ))
      )}
    </div>
  );
}
