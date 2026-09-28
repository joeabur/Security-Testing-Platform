import type { Metadata } from "next";
import Link from "next/link";
import { Activity } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Run, Target } from "@/lib/types";

export const metadata: Metadata = { title: "Runs — Aegis AI Security" };

const STATUS_STYLES: Record<string, string> = {
  completed: "bg-severity-low/15 text-severity-low",
  running: "bg-primary/15 text-primary",
  queued: "bg-muted text-muted-foreground",
  failed: "bg-destructive/15 text-destructive",
  cancelled: "bg-muted text-muted-foreground",
  expired: "bg-destructive/15 text-destructive",
};

export default async function RunsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [runs, targets] = await Promise.all([
    serverApiFetch<Run[]>(`/organizations/${id}/runs`),
    serverApiFetch<Target[]>(`/organizations/${id}/targets`),
  ]);
  const targetNames = new Map(targets.map((target) => [target.id, target.name]));

  return (
    <div className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold">Runs</h2>
      {runs.length === 0 ? (
        <Card>
          <CardHeader className="items-center text-center">
            <Activity className="h-8 w-8 text-muted-foreground" aria-hidden />
            <CardDescription>
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
              <Card className="transition-colors hover:border-primary">
                <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                  <div>
                    <p className="font-medium">{targetNames.get(run.target_id) ?? run.target_id}</p>
                    <p className="text-sm text-muted-foreground">
                      {run.profile} · {run.checks_completed}/{run.checks_total} checks ·{" "}
                      {run.findings_reported} findings
                    </p>
                  </div>
                  <span
                    className={`rounded-full px-2.5 py-1 text-xs font-medium ${
                      STATUS_STYLES[run.status] ?? "bg-muted text-muted-foreground"
                    }`}
                  >
                    {run.status}
                  </span>
                </CardContent>
              </Card>
            </Link>
          ))
      )}
    </div>
  );
}
