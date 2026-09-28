import type { Metadata } from "next";

import { AuthorizationGrantForm } from "@/components/targets/authorization-grant-form";
import { RulesOfEngagementForm } from "@/components/targets/rules-of-engagement-form";
import { StartRunForm } from "@/components/runs/start-run-form";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Authorization, RulesOfEngagement, Target } from "@/lib/types";

export const metadata: Metadata = { title: "Target — Aegis AI Security" };

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
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="text-xl font-semibold">{target.name}</h2>
        <p className="text-sm text-muted-foreground">
          {target.base_url} · {target.environment} · {target.kind}
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Rules of Engagement</CardTitle>
          <CardDescription>
            {roe
              ? "Configured. Saving again replaces it wholesale."
              : "Required before a run can start — defines what an assessment is allowed to touch."}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {roe && (
            <dl className="grid gap-2 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-muted-foreground">Allowed domains</dt>
                <dd>{roe.allowed_domains.join(", ") || "—"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Allowed IP ranges</dt>
                <dd>{roe.allowed_ip_ranges.join(", ") || "—"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Allowed paths</dt>
                <dd>{roe.allowed_paths.join(", ") || "—"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Allowed methods</dt>
                <dd>{roe.allowed_methods.join(", ") || "—"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Safe mode</dt>
                <dd>{roe.safe_mode ? "On" : "Off"}</dd>
              </div>
            </dl>
          )}
          <RulesOfEngagementForm organizationId={id} targetId={targetId} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Authorization</CardTitle>
          <CardDescription>
            {authorization
              ? "Granted. Submitting again replaces it."
              : "The human act the platform is built around — someone taking responsibility for testing this target."}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {authorization && (
            <dl className="grid gap-2 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-muted-foreground">Authorized by</dt>
                <dd>
                  {authorization.authorized_by_name} ({authorization.authorized_by_role})
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Reference</dt>
                <dd>{authorization.reference}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Valid from</dt>
                <dd>{new Date(authorization.valid_from).toLocaleString()}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Valid until</dt>
                <dd>{new Date(authorization.valid_until).toLocaleString()}</dd>
              </div>
            </dl>
          )}
          <AuthorizationGrantForm organizationId={id} targetId={targetId} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Start a run</CardTitle>
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
