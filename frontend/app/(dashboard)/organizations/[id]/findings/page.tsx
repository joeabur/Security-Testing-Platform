import type { Metadata } from "next";
import Link from "next/link";
import { ShieldAlert } from "lucide-react";

import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Select } from "@/components/ui/select";
import { serverApiFetch } from "@/lib/api-server";
import type { Finding, FindingStatus, Severity, Target } from "@/lib/types";

export const metadata: Metadata = { title: "Findings — Kervy Security" };

const PAGE_SIZE = 25;

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

export default async function FindingsPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{
    severity?: string;
    status?: string;
    page?: string;
    include_duplicates?: string;
  }>;
}) {
  const { id } = await params;
  const query = await searchParams;
  const page = Math.max(1, Number.parseInt(query.page ?? "1", 10) || 1);
  const offset = (page - 1) * PAGE_SIZE;
  const includeDuplicates = query.include_duplicates === "true";

  const apiParams = new URLSearchParams();
  if (query.severity) apiParams.set("severity", query.severity);
  if (query.status) apiParams.set("finding_status", query.status);
  if (includeDuplicates) apiParams.set("include_duplicates", "true");
  // One extra row, never rendered — its presence is how "Next" is decided
  // without a second request or a total count the API doesn't return.
  apiParams.set("limit", String(PAGE_SIZE + 1));
  apiParams.set("offset", String(offset));

  const [rows, targets] = await Promise.all([
    serverApiFetch<Finding[]>(`/organizations/${id}/findings?${apiParams.toString()}`),
    serverApiFetch<Target[]>(`/organizations/${id}/targets`),
  ]);
  const hasMore = rows.length > PAGE_SIZE;
  const findings = rows.slice(0, PAGE_SIZE);
  const targetNames = new Map(targets.map((target) => [target.id, target.name]));

  function pageHref(nextPage: number): string {
    const href = new URLSearchParams();
    if (query.severity) href.set("severity", query.severity);
    if (query.status) href.set("status", query.status);
    if (includeDuplicates) href.set("include_duplicates", "true");
    if (nextPage > 1) href.set("page", String(nextPage));
    const suffix = href.toString();
    return `/organizations/${id}/findings${suffix ? `?${suffix}` : ""}`;
  }

  return (
    <div className="flex animate-fade-in flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold">Findings</h2>
        <p className="text-sm text-muted-foreground">
          Every finding this organization has open or has ever seen, worst first by risk score.
        </p>
      </div>

      <form
        method="get"
        className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-card p-3"
      >
        <div className="flex flex-col gap-1">
          <label htmlFor="severity" className="text-xs font-medium text-muted-foreground">
            Severity
          </label>
          <Select id="severity" name="severity" defaultValue={query.severity ?? ""} className="w-44">
            <option value="">All severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFORMATIONAL">Informational</option>
          </Select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="status" className="text-xs font-medium text-muted-foreground">
            Status
          </label>
          <Select id="status" name="status" defaultValue={query.status ?? ""} className="w-48">
            <option value="">All statuses</option>
            <option value="new">New</option>
            <option value="confirmed">Confirmed</option>
            <option value="false_positive">False positive</option>
            <option value="accepted_risk">Accepted risk</option>
            <option value="in_remediation">In remediation</option>
            <option value="remediated">Remediated</option>
            <option value="retest_required">Retest required</option>
            <option value="closed">Closed</option>
          </Select>
        </div>
        <div className="flex items-center gap-2 pb-2">
          <Checkbox
            id="include_duplicates"
            name="include_duplicates"
            value="true"
            defaultChecked={includeDuplicates}
          />
          <label htmlFor="include_duplicates" className="text-sm text-muted-foreground">
            Include findings linked as duplicates
          </label>
        </div>
        <Button type="submit" size="sm">
          Apply filters
        </Button>
        {(query.severity || query.status || includeDuplicates) && (
          <Link
            href={`/organizations/${id}/findings`}
            className="text-sm font-medium text-muted-foreground hover:text-foreground"
          >
            Clear
          </Link>
        )}
      </form>

      {findings.length === 0 ? (
        <Card className="border-dashed shadow-none">
          <CardHeader className="items-center py-10 text-center">
            <span className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
              <ShieldAlert className="h-6 w-6" aria-hidden />
            </span>
            <CardTitle className="mt-2 text-base">No findings match these filters</CardTitle>
          </CardHeader>
        </Card>
      ) : (
        <Card className="overflow-hidden p-0">
          <table className="w-full text-sm">
            <thead className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground">
              <tr>
                <th className="px-4 py-2.5 font-medium">Finding</th>
                <th className="px-4 py-2.5 font-medium">Target</th>
                <th className="px-4 py-2.5 font-medium">Severity</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-4 py-2.5 font-medium">Risk</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id} className="border-b border-border last:border-0 hover:bg-muted/30">
                  <td className="px-4 py-3">
                    <Link
                      href={`/organizations/${id}/findings/${finding.id}`}
                      className="font-medium text-foreground hover:text-primary hover:underline"
                    >
                      {finding.title}
                    </Link>
                    {finding.duplicate_of_finding_id && (
                      <Badge tone="neutral" className="ml-2">
                        Duplicate
                      </Badge>
                    )}
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {finding.target_id ? targetNames.get(finding.target_id) ?? "Unknown target" : "—"}
                  </td>
                  <td className="px-4 py-3">
                    <Badge tone={SEVERITY_TONE[finding.severity]} dot>
                      {finding.severity}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <Badge tone={STATUS_TONE[finding.status]}>{statusLabel(finding.status)}</Badge>
                  </td>
                  <td className="px-4 py-3 tabular-nums text-muted-foreground">
                    {finding.risk_score.toFixed(1)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {(page > 1 || hasMore) && (
        <div className="flex items-center justify-between">
          <Link
            href={pageHref(page - 1)}
            aria-disabled={page <= 1}
            className={
              page <= 1
                ? "pointer-events-none text-sm text-muted-foreground/50"
                : "text-sm font-medium text-primary hover:underline"
            }
          >
            ← Previous
          </Link>
          <span className="text-xs text-muted-foreground">Page {page}</span>
          <Link
            href={pageHref(page + 1)}
            aria-disabled={!hasMore}
            className={
              hasMore
                ? "text-sm font-medium text-primary hover:underline"
                : "pointer-events-none text-sm text-muted-foreground/50"
            }
          >
            Next →
          </Link>
        </div>
      )}
    </div>
  );
}
