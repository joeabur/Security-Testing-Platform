import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

import { FindingDuplicateForm } from "@/components/findings/finding-duplicate-form";
import { FindingStatusForm } from "@/components/findings/finding-status-form";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { Finding, FindingStatus, Severity, Target } from "@/lib/types";

const SEVERITY_TONE: Record<Severity, BadgeProps["tone"]> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFORMATIONAL: "info",
};

const STATUS_TONE: Record<FindingStatus, BadgeProps["tone"]> = {
  new: "primary",
  confirmed: "warning",
  false_positive: "neutral",
  accepted_risk: "outline",
  in_remediation: "warning",
  remediated: "success",
  retest_required: "warning",
  closed: "neutral",
};

function statusLabel(status: FindingStatus): string {
  return status.replace(/_/g, " ");
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string; findingId: string }>;
}): Promise<Metadata> {
  const { id, findingId } = await params;
  const finding = await serverApiFetch<Finding>(`/organizations/${id}/findings/${findingId}`);
  return { title: `${finding.title} — Kervy Security` };
}

export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ id: string; findingId: string }>;
}) {
  const { id, findingId } = await params;
  const finding = await serverApiFetch<Finding>(`/organizations/${id}/findings/${findingId}`);
  const target = finding.target_id
    ? await serverApiFetch<Target>(`/organizations/${id}/targets/${finding.target_id}`).catch(
        () => null,
      )
    : null;
  const duplicates = await serverApiFetch<Finding[]>(
    `/organizations/${id}/findings/${findingId}/duplicates`,
  );

  return (
    <div className="flex max-w-4xl animate-fade-in flex-col gap-4">
      <Link
        href={`/organizations/${id}/findings`}
        className="flex items-center gap-1.5 text-sm font-medium text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" aria-hidden />
        Back to findings
      </Link>

      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{finding.title}</h1>
          <p className="text-sm text-muted-foreground">
            {target ? target.name : "No target"} · {finding.probe_id} · seen {finding.times_seen}{" "}
            time{finding.times_seen === 1 ? "" : "s"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge tone={SEVERITY_TONE[finding.severity]} dot>
            {finding.severity}
          </Badge>
          <Badge tone={STATUS_TONE[finding.status]}>{statusLabel(finding.status)}</Badge>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="flex flex-col gap-4 md:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Description</CardTitle>
            </CardHeader>
            <CardContent className="whitespace-pre-wrap text-sm text-foreground">
              {finding.description}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Impact</CardTitle>
            </CardHeader>
            <CardContent className="whitespace-pre-wrap text-sm text-foreground">
              {finding.impact}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Remediation</CardTitle>
            </CardHeader>
            <CardContent className="whitespace-pre-wrap text-sm text-foreground">
              {finding.remediation}
            </CardContent>
          </Card>

          {finding.reproduction.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Reproduction</CardTitle>
              </CardHeader>
              <CardContent>
                <ol className="flex list-decimal flex-col gap-1.5 pl-4 text-sm text-foreground">
                  {finding.reproduction.map((step, index) => (
                    <li key={index}>{step}</li>
                  ))}
                </ol>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Severity rationale</CardTitle>
            </CardHeader>
            <CardContent className="whitespace-pre-wrap text-sm text-foreground">
              {finding.severity_rationale}
            </CardContent>
          </Card>
        </div>

        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Change status</CardTitle>
              <CardDescription>
                Transitions are restricted so a closed finding stays auditable.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <FindingStatusForm organizationId={id} finding={finding} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Duplicate</CardTitle>
              <CardDescription>
                A human&apos;s explicit judgment that this and another finding describe the same
                underlying defect — never inferred automatically.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <FindingDuplicateForm organizationId={id} finding={finding} />
            </CardContent>
          </Card>

          {duplicates.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Duplicates of this finding</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="flex flex-col gap-2 text-sm">
                  {duplicates.map((duplicate) => (
                    <li key={duplicate.id}>
                      <Link
                        href={`/organizations/${id}/findings/${duplicate.id}`}
                        className="font-medium text-foreground hover:text-primary hover:underline"
                      >
                        {duplicate.title}
                      </Link>
                      <span className="ml-2 text-xs text-muted-foreground">
                        {duplicate.severity}
                      </span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Details</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-2 text-sm">
              <Row label="Category">{finding.category}</Row>
              <Row label="Confidence">{finding.confidence}</Row>
              <Row label="Stability">{finding.stability}</Row>
              <Row label="Risk score">{finding.risk_score.toFixed(1)} / 10</Row>
              <Row label="Risk model">{finding.risk_model}</Row>
              <Row label="First seen">{new Date(finding.first_seen).toLocaleString()}</Row>
              <Row label="Last seen">{new Date(finding.last_seen).toLocaleString()}</Row>
              {finding.retest_result && <Row label="Last retest">{finding.retest_result}</Row>}
              {finding.status_note && (
                <div className="pt-1">
                  <p className="text-xs text-muted-foreground">Status note</p>
                  <p className="mt-0.5 whitespace-pre-wrap">{finding.status_note}</p>
                </div>
              )}
              {finding.evidence_ref && (
                <div className="pt-1">
                  <p className="text-xs text-muted-foreground">Evidence digest</p>
                  <code className="mt-0.5 block truncate text-xs">{finding.evidence_ref}</code>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right font-medium text-foreground">{children}</span>
    </div>
  );
}
