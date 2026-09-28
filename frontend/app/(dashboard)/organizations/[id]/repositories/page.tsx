import type { Metadata } from "next";
import { GitBranch } from "lucide-react";

import { AddRepositoryForm } from "@/components/repositories/add-repository-form";
import { ScanRepositoryButton } from "@/components/repositories/scan-repository-button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Repository } from "@/lib/types";

export const metadata: Metadata = { title: "Repositories — Aegis AI Security" };

export default async function RepositoriesPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const repositories = await serverApiFetch<Repository[]>(`/organizations/${id}/repositories`);

  return (
    <div className="flex flex-col gap-6">
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
          <Card>
            <CardHeader className="items-center text-center">
              <GitBranch className="h-8 w-8 text-muted-foreground" aria-hidden />
              <CardDescription>No repositories connected yet.</CardDescription>
            </CardHeader>
          </Card>
        ) : (
          repositories.map((repo) => (
            <Card key={repo.id}>
              <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                <div>
                  <p className="font-medium">{repo.name}</p>
                  <p className="text-sm text-muted-foreground">
                    {repo.url}
                    {repo.branch ? ` @ ${repo.branch}` : ""}
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {repo.latest_scan
                      ? `Latest scan: ${repo.latest_scan.status}`
                      : "No scans yet"}
                  </p>
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
