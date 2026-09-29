import type { Metadata } from "next";
import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardList,
  PlayCircle,
  RefreshCw,
  ShieldAlert,
  Workflow as WorkflowIcon,
  XCircle,
} from "lucide-react";

import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import type { DashboardSummary, Severity } from "@/lib/types";

export const metadata: Metadata = { title: "Overview — Kervy Security" };

const SEVERITY_TONE: Record<Severity, BadgeProps["tone"]> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFORMATIONAL: "info",
};

const RUN_STATUS_TONE: Record<string, BadgeProps["tone"]> = {
  completed: "success",
  running: "primary",
  queued: "neutral",
  failed: "destructive",
  cancelled: "neutral",
  expired: "destructive",
};

function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = "neutral",
}: {
  label: string;
  value: number;
  sub?: string;
  icon: React.ComponentType<{ className?: string }>;
  tone?: "neutral" | "warning" | "destructive";
}) {
  const toneClasses =
    tone === "destructive"
      ? "bg-destructive/10 text-destructive"
      : tone === "warning"
        ? "bg-warning/10 text-warning"
        : "bg-primary/10 text-primary";
  return (
    <Card>
      <CardContent className="flex items-start justify-between gap-3 py-5">
        <div>
          <p className="text-sm text-muted-foreground">{label}</p>
          <p className="mt-1 text-2xl font-semibold tracking-tight">{value}</p>
          {sub && <p className="mt-0.5 text-xs text-muted-foreground">{sub}</p>}
        </div>
        <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${toneClasses}`}>
          <Icon className="h-4 w-4" />
        </span>
      </CardContent>
    </Card>
  );
}

export default async function OrganizationOverviewPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const summary = await serverApiFetch<DashboardSummary>(`/organizations/${id}/dashboard/summary`);
  const s = summary.open_findings_by_severity;

  return (
    <div className="flex animate-fade-in flex-col gap-6">
      <div>
        <h2 className="text-lg font-semibold">Security overview</h2>
        <p className="text-sm text-muted-foreground">
          Open risk, recent activity, and coverage across this organization.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Open findings"
          value={summary.open_findings}
          sub={`${s.critical} critical · ${s.high} high`}
          icon={ShieldAlert}
          tone={s.critical > 0 ? "destructive" : s.high > 0 ? "warning" : "neutral"}
        />
        <StatCard
          label="Runs, last 7 days"
          value={summary.runs_last_7_days}
          sub={`${summary.failed_runs_last_7_days} failed`}
          icon={PlayCircle}
          tone={summary.failed_runs_last_7_days > 0 ? "warning" : "neutral"}
        />
        <StatCard
          label="Failing gates, last 7 days"
          value={summary.failing_gates_last_7_days}
          sub={`${summary.workflows} workflows configured`}
          icon={WorkflowIcon}
          tone={summary.failing_gates_last_7_days > 0 ? "warning" : "neutral"}
        />
        <StatCard
          label="Remediation open"
          value={summary.remediation.open}
          sub={`${summary.remediation.overdue} overdue · ${summary.pending_retests} awaiting retest`}
          icon={ClipboardList}
          tone={summary.remediation.overdue > 0 ? "destructive" : "neutral"}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Open findings by severity</CardTitle>
          <CardDescription>Excludes closed, false-positive, accepted-risk, and remediated findings.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {(
            [
              ["CRITICAL", s.critical],
              ["HIGH", s.high],
              ["MEDIUM", s.medium],
              ["LOW", s.low],
              ["INFORMATIONAL", s.informational],
            ] as [Severity, number][]
          ).map(([severity, count]) => (
            <Badge key={severity} tone={SEVERITY_TONE[severity]} dot>
              {severity.charAt(0) + severity.slice(1).toLowerCase()}: {count}
            </Badge>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Coverage by pillar</CardTitle>
          <CardDescription>
            Whether any run in this organization has ever produced a real result for each
            assessment pillar — not whether it was configured to.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {summary.pillar_coverage.map((entry) => (
            <Badge key={entry.pillar} tone={entry.tested ? "success" : "outline"}>
              {entry.tested ? (
                <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
              ) : (
                <XCircle className="h-3.5 w-3.5" aria-hidden />
              )}
              {entry.pillar}
            </Badge>
          ))}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Recent runs</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {summary.recent_runs.length === 0 ? (
              <p className="text-sm text-muted-foreground">No runs yet.</p>
            ) : (
              summary.recent_runs.map((run) => (
                <Link
                  key={run.id}
                  href={`/organizations/${id}/runs/${run.id}`}
                  className="flex items-center justify-between gap-3 rounded-md border border-border p-3 text-sm transition-colors hover:border-primary/40 hover:bg-muted/40"
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium">{run.target_name}</p>
                    <p className="text-xs text-muted-foreground">
                      {run.profile} · {run.findings_reported} findings
                    </p>
                  </div>
                  <Badge tone={RUN_STATUS_TONE[run.status] ?? "neutral"} dot>
                    {run.status}
                  </Badge>
                </Link>
              ))
            )}
            <Link
              href={`/organizations/${id}/runs`}
              className="mt-1 text-xs font-medium text-primary hover:underline"
            >
              View all runs
            </Link>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent workflow runs</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {summary.recent_workflow_runs.length === 0 ? (
              <p className="text-sm text-muted-foreground">No workflow runs yet.</p>
            ) : (
              summary.recent_workflow_runs.map((run) => (
                <div
                  key={run.id}
                  className="flex items-center justify-between gap-3 rounded-md border border-border p-3 text-sm"
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium">{run.workflow_name}</p>
                    <p className="text-xs text-muted-foreground">{run.status}</p>
                  </div>
                  {run.gate_passed === null ? (
                    <Badge tone="neutral">Not decided</Badge>
                  ) : run.gate_passed ? (
                    <Badge tone="success" dot>
                      Gate passed
                    </Badge>
                  ) : (
                    <Badge tone="destructive" dot>
                      Gate failed
                    </Badge>
                  )}
                </div>
              ))
            )}
            <Link
              href={`/organizations/${id}/workflows`}
              className="mt-1 text-xs font-medium text-primary hover:underline"
            >
              View all workflows
            </Link>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-muted-foreground" aria-hidden />
            <CardTitle>Top findings</CardTitle>
          </div>
          <CardDescription>Open findings, worst first by risk score.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {summary.top_findings.length === 0 ? (
            <p className="text-sm text-muted-foreground">No open findings.</p>
          ) : (
            summary.top_findings.map((finding) => (
              <div
                key={finding.id}
                className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-2 text-sm last:border-0"
              >
                <div className="min-w-0">
                  <p className="truncate font-medium">{finding.title}</p>
                  <p className="text-xs text-muted-foreground">
                    {finding.target_name ?? "Unknown target"} · risk {finding.risk_score.toFixed(1)}
                  </p>
                </div>
                <Badge tone={SEVERITY_TONE[finding.severity]} dot>
                  {finding.severity}
                </Badge>
              </div>
            ))
          )}
          {summary.pending_retests > 0 && (
            <p className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
              <RefreshCw className="h-3.5 w-3.5" aria-hidden />
              {summary.pending_retests} finding{summary.pending_retests === 1 ? "" : "s"} awaiting
              retest confirmation.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
