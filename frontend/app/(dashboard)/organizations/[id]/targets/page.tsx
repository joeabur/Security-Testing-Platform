import type { Metadata } from "next";
import Link from "next/link";
import { Crosshair } from "lucide-react";

import { CreateTargetForm } from "@/components/targets/create-target-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Target } from "@/lib/types";

export const metadata: Metadata = { title: "Targets — Aegis AI Security" };

export default async function TargetsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const targets = await serverApiFetch<Target[]>(`/organizations/${id}/targets`);

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Add a target</CardTitle>
          <CardDescription>
            A live network target — a web app, API, or LLM application. Running an assessment
            against it needs Rules of Engagement and an authorization grant first, configured
            from the target&apos;s page after you add it.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <CreateTargetForm organizationId={id} />
        </CardContent>
      </Card>

      <div className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">Targets</h2>
        {targets.length === 0 ? (
          <Card>
            <CardHeader className="items-center text-center">
              <Crosshair className="h-8 w-8 text-muted-foreground" aria-hidden />
              <CardDescription>No targets yet.</CardDescription>
            </CardHeader>
          </Card>
        ) : (
          targets.map((target) => (
            <Link key={target.id} href={`/organizations/${id}/targets/${target.id}`}>
              <Card className="transition-colors hover:border-primary">
                <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                  <div>
                    <p className="font-medium">{target.name}</p>
                    <p className="text-sm text-muted-foreground">
                      {target.base_url} · {target.environment} · {target.kind}
                    </p>
                  </div>
                  <div className="flex gap-2 text-xs">
                    <span
                      className={
                        target.has_rules_of_engagement
                          ? "rounded-full bg-muted px-2 py-1 text-foreground"
                          : "rounded-full border border-dashed border-border px-2 py-1 text-muted-foreground"
                      }
                    >
                      {target.has_rules_of_engagement ? "RoE set" : "No RoE"}
                    </span>
                    <span
                      className={
                        target.has_authorization
                          ? "rounded-full bg-muted px-2 py-1 text-foreground"
                          : "rounded-full border border-dashed border-border px-2 py-1 text-muted-foreground"
                      }
                    >
                      {target.has_authorization ? "Authorized" : "Not authorized"}
                    </span>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))
        )}
      </div>
    </div>
  );
}
