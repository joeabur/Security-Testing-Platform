import type { Metadata } from "next";
import { GitBranch } from "lucide-react";

import { AddRepositoryForm } from "@/components/repositories/add-repository-form";
import { ScanRepositoryButton } from "@/components/repositories/scan-repository-button";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Repository } from "@/lib/types";

const SCAN_STATUS_TONE: Record<string, BadgeProps["tone"]> = {
  completed: "success",
  running: "primary",
  queued: "neutral",
  failed: "destructive",
  cancelled: "neutral",
  expired: "destructive",
};

export const metadata: Metadata = { title: "Repositories — Kervy Security" };

export default async function RepositoriesPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const repositories = await serverApiFetch<Repository[]>(`/organizations/${id}/repositories`);

  return (
    <div className="flex animate-fade-in flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Connect a repository</CardTitle>
          <CardDescription>
            The lightweight path onto code scanning (SAST, SCA, secrets, IaC) — no
            Rules-of-Engagement or authorization-grant workflow needed, just an affirmation that
            you may have this repository scanned.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AddRepositoryForm organizationId={id} />
        </CardContent>
      </Card>

      <div className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">Connected repositories</h2>
        {repositories.length === 0 ? (
          <Card className="border-dashed shadow-none">
            <CardHeader className="items-center py-10 text-center">
              <span className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
                <GitBranch className="h-6 w-6" aria-hidden />
              </span>
              <CardDescription className="mt-1">No repositories connected yet.</CardDescription>
            </CardHeader>
          </Card>
        ) : (
          repositories.map((repo) => (
            <Card key={repo.id} className="transition-shadow duration-150 hover:shadow-elevated">
              <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                <div>
                  <p className="font-medium">{repo.name}</p>
                  <p className="text-sm text-muted-foreground">
                    {repo.url}
                    {repo.branch ? ` @ ${repo.branch}` : ""}
                  </p>
                  <div className="mt-2">
                    {repo.latest_scan ? (
                      <Badge tone={SCAN_STATUS_TONE[repo.latest_scan.status] ?? "neutral"} dot>
                        Latest scan: {repo.latest_scan.status}
                      </Badge>
                    ) : (
                      <Badge tone="outline">No scans yet</Badge>
                    )}
                  </div>
                </div>
                <ScanRepositoryButton organizationId={id} repositoryId={repo.id} />
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
