import type { Metadata } from "next";
import Link from "next/link";
import { Crosshair } from "lucide-react";

import { CreateTargetForm } from "@/components/targets/create-target-form";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Target } from "@/lib/types";

export const metadata: Metadata = { title: "Targets — Kervy Security" };

export default async function TargetsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const targets = await serverApiFetch<Target[]>(`/organizations/${id}/targets`);

  return (
    <div className="flex animate-fade-in flex-col gap-6">
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
          <Card className="border-dashed shadow-none">
            <CardHeader className="items-center py-10 text-center">
              <span className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
                <Crosshair className="h-6 w-6" aria-hidden />
              </span>
              <CardDescription className="mt-1">No targets yet.</CardDescription>
            </CardHeader>
          </Card>
        ) : (
          targets.map((target) => (
            <Link key={target.id} href={`/organizations/${id}/targets/${target.id}`}>
              <Card className="transition-all duration-150 hover:border-primary/40 hover:shadow-elevated">
                <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                  <div>
                    <p className="font-medium">{target.name}</p>
                    <p className="text-sm text-muted-foreground">
                      {target.base_url} · {target.environment} · {target.kind}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Badge tone={target.has_rules_of_engagement ? "success" : "outline"} dot>
                      {target.has_rules_of_engagement ? "RoE set" : "No RoE"}
                    </Badge>
                    <Badge tone={target.has_authorization ? "success" : "outline"} dot>
                      {target.has_authorization ? "Authorized" : "Not authorized"}
                    </Badge>
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
