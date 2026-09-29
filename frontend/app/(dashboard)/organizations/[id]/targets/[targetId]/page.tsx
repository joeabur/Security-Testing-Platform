import type { Metadata } from "next";
import { ClipboardCheck, PlayCircle, ShieldCheck } from "lucide-react";

import { AuthorizationGrantForm } from "@/components/targets/authorization-grant-form";
import { RulesOfEngagementForm } from "@/components/targets/rules-of-engagement-form";
import { StartRunForm } from "@/components/runs/start-run-form";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Authorization, RulesOfEngagement, Target } from "@/lib/types";

export const metadata: Metadata = { title: "Target — Kervy Security" };

export default async function TargetDetailPage({
  params,
}: {
  params: Promise<{ id: string; targetId: string }>;
}) {
  const { id, targetId } = await params;
  const target = await serverApiFetch<Target>(`/organizations/${id}/targets/${targetId}`);

  const [roe, authorization] = await Promise.all([
    target.has_rules_of_engagement
      ? serverApiFetch<RulesOfEngagement>(
          `/organizations/${id}/targets/${targetId}/rules-of-engagement`,
        )
      : Promise.resolve(null),
    target.has_authorization
      ? serverApiFetch<Authorization>(`/organizations/${id}/targets/${targetId}/authorization`)
      : Promise.resolve(null),
  ]);

  const readyToRun = Boolean(roe) && Boolean(authorization);

  return (
    <div className="flex animate-fade-in flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold">{target.name}</h2>
          <p className="text-sm text-muted-foreground">
            {target.base_url} · {target.environment} · {target.kind}
          </p>
        </div>
        <div className="flex gap-2">
          <Badge tone={roe ? "success" : "outline"} dot>
            RoE {roe ? "set" : "missing"}
          </Badge>
          <Badge tone={authorization ? "success" : "outline"} dot>
            {authorization ? "Authorized" : "Not authorized"}
          </Badge>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
            <CardTitle>Rules of Engagement</CardTitle>
          </div>
          <CardDescription>
            {roe
              ? "Configured. Saving again replaces it wholesale."
              : "Required before a run can start — defines what an assessment is allowed to touch."}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {roe && (
            <dl className="grid divide-y divide-border rounded-lg border border-border bg-muted/40 text-sm sm:grid-cols-2 sm:divide-x sm:divide-y-0">
              <div className="flex flex-col gap-0.5 px-4 py-3">
                <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Allowed domains
                </dt>
                <dd>{roe.allowed_domains.join(", ") || "—"}</dd>
              </div>
              <div className="flex flex-col gap-0.5 px-4 py-3">
                <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Allowed IP ranges
                </dt>
                <dd>{roe.allowed_ip_ranges.join(", ") || "—"}</dd>
              </div>
              <div className="flex flex-col gap-0.5 px-4 py-3">
                <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Allowed paths
                </dt>
                <dd>{roe.allowed_paths.join(", ") || "—"}</dd>
              </div>
              <div className="flex flex-col gap-0.5 px-4 py-3">
                <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Allowed methods
                </dt>
                <dd>{roe.allowed_methods.join(", ") || "—"}</dd>
              </div>
              <div className="flex flex-col gap-0.5 px-4 py-3">
                <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Safe mode
                </dt>
                <dd>
                  <Badge tone={roe.safe_mode ? "success" : "warning"}>
                    {roe.safe_mode ? "On" : "Off"}
                  </Badge>
                </dd>
              </div>
            </dl>
          )}
          <RulesOfEngagementForm organizationId={id} targetId={targetId} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <ClipboardCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
            <CardTitle>Authorization</CardTitle>
          </div>
          <CardDescription>
            {authorization
              ? "Granted. Submitting again replaces it."
              : "The human act the platform is built around — someone taking responsibility for testing this target."}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {authorization && (
            <dl className="grid divide-y divide-border rounded-lg border border-border bg-muted/40 text-sm sm:grid-cols-2 sm:divide-x sm:divide-y-0">
              <div className="flex flex-col gap-0.5 px-4 py-3">
                <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Authorized by
                </dt>
                <dd>
                  {authorization.authorized_by_name} ({authorization.authorized_by_role})
                </dd>
              </div>
              <div className="flex flex-col gap-0.5 px-4 py-3">
                <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Reference
                </dt>
                <dd>{authorization.reference}</dd>
              </div>
              <div className="flex flex-col gap-0.5 px-4 py-3">
                <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Valid from
                </dt>
                <dd>{new Date(authorization.valid_from).toLocaleString()}</dd>
              </div>
              <div className="flex flex-col gap-0.5 px-4 py-3">
                <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Valid until
                </dt>
                <dd>{new Date(authorization.valid_until).toLocaleString()}</dd>
              </div>
            </dl>
          )}
          <AuthorizationGrantForm organizationId={id} targetId={targetId} />
        </CardContent>
      </Card>

      <Card className={readyToRun ? "border-primary/30" : undefined}>
        <CardHeader>
          <div className="flex items-center gap-2">
            <PlayCircle className="h-4 w-4 text-muted-foreground" aria-hidden />
            <CardTitle>Start a run</CardTitle>
          </div>
          <CardDescription>
            {readyToRun
              ? "Rules of Engagement and authorization are both on file."
              : "Set Rules of Engagement and authorization above before starting a run — the API refuses otherwise."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {readyToRun ? (
            <StartRunForm organizationId={id} targetId={targetId} />
          ) : (
            <p className="text-sm text-muted-foreground">Not ready yet.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
