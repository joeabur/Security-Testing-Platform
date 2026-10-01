"use client";

import { useEffect, useState } from "react";

import { ExploitationFires } from "@/components/runs/exploitation-fires";
import { ReportDownload } from "@/components/runs/report-download";
import { Alert } from "@/components/ui/alert";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { clientApiFetch } from "@/lib/api-client";
import { TERMINAL_RUN_STATUSES, type Run, type RunEvent } from "@/lib/types";

// Mirrors _NOT_YET_RUN in app/api/v1/routers/reports.py: a report is only
// meaningful once the run has actually executed.
const NOT_YET_RUN: readonly Run["status"][] = ["draft", "queued"];

const POLL_MS = 2000;

const STATUS_TONE: Record<string, BadgeProps["tone"]> = {
  completed: "success",
  running: "primary",
  queued: "neutral",
  failed: "destructive",
  cancelled: "neutral",
  expired: "destructive",
};

export function RunDetail({
  organizationId,
  runId,
  initialRun,
}: {
  organizationId: string;
  runId: string;
  initialRun: Run;
}) {
  const [run, setRun] = useState(initialRun);
  const [events, setEvents] = useState<RunEvent[]>([]);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function poll() {
      try {
        const [latestRun, latestEvents] = await Promise.all([
          clientApiFetch<Run>(`/organizations/${organizationId}/runs/${runId}`),
          clientApiFetch<RunEvent[]>(`/organizations/${organizationId}/runs/${runId}/events`),
        ]);
        if (cancelled) return;
        setRun(latestRun);
        setEvents(latestEvents);
        if (!TERMINAL_RUN_STATUSES.includes(latestRun.status)) {
          timer = setTimeout(poll, POLL_MS);
        }
      } catch {
        // A transient fetch failure just skips this tick — the next poll
        // (or a manual reload) picks it back up rather than surfacing an
        // error for what is often just one dropped request.
        if (!cancelled) {
          timer = setTimeout(poll, POLL_MS);
        }
      }
    }

    if (!TERMINAL_RUN_STATUSES.includes(initialRun.status)) {
      timer = setTimeout(poll, POLL_MS);
    } else {
      clientApiFetch<RunEvent[]>(`/organizations/${organizationId}/runs/${runId}/events`)
        .then((initialEvents) => {
          if (!cancelled) setEvents(initialEvents);
        })
        .catch(() => {});
    }

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [organizationId, runId]);

  const isLive = !TERMINAL_RUN_STATUSES.includes(run.status);
  const progress = run.checks_total > 0 ? Math.round((run.checks_completed / run.checks_total) * 100) : 0;

  return (
    <div className="flex animate-fade-in flex-col gap-6">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <CardTitle>Run status</CardTitle>
            <Badge tone={STATUS_TONE[run.status] ?? "neutral"} dot>
              {run.status}
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          {run.checks_total > 0 && (
            <div className="mb-5">
              <div className="mb-1.5 flex justify-between text-xs text-muted-foreground">
                <span>
                  {run.checks_completed}/{run.checks_total} checks
                </span>
                <span>{progress}%</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-primary transition-[width] duration-500 ease-out"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}

          <dl className="grid divide-y divide-border rounded-lg border border-border bg-muted/40 text-sm sm:grid-cols-3 sm:divide-x sm:divide-y-0">
            <div className="flex flex-col gap-0.5 px-4 py-3">
              <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Requests used
              </dt>
              <dd>{run.requests_used}</dd>
            </div>
            <div className="flex flex-col gap-0.5 px-4 py-3">
              <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Requests blocked
              </dt>
              <dd>{run.requests_blocked}</dd>
            </div>
            <div className="flex flex-col gap-0.5 px-4 py-3">
              <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Findings
              </dt>
              <dd>{run.findings_reported}</dd>
            </div>
            <div className="flex flex-col gap-0.5 px-4 py-3">
              <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Profile
              </dt>
              <dd>{run.profile}</dd>
            </div>
            <div className="flex flex-col gap-0.5 px-4 py-3 sm:col-span-2">
              <dt className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Safe mode
              </dt>
              <dd>
                <Badge tone={run.safe_mode ? "success" : "warning"}>{run.safe_mode ? "On" : "Off"}</Badge>
              </dd>
            </div>
          </dl>

          {run.halted_reason && (
            <Alert tone="warning" className="mt-4">
              Halted: {run.halted_reason}
            </Alert>
          )}
          {run.error_message && (
            <Alert tone="destructive" className="mt-4">
              Error: {run.error_message}
            </Alert>
          )}
          {isLive && (
            <p className="mt-4 flex items-center gap-1.5 text-xs text-muted-foreground">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
              </span>
              Updating every few seconds…
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Events</CardTitle>
        </CardHeader>
        <CardContent>
          {events.length === 0 ? (
            <p className="text-sm text-muted-foreground">No events yet.</p>
          ) : (
            <ul className="scrollbar-thin flex max-h-96 flex-col gap-2 overflow-y-auto text-sm">
              {events.map((event) => (
                <li key={event.seq} className="border-b border-border pb-2 last:border-0">
                  <span className="font-mono text-xs text-muted-foreground">
                    {new Date(event.occurred_at).toLocaleTimeString()}
                  </span>{" "}
                  <span className="font-medium">{event.kind}</span> — {event.message}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {!NOT_YET_RUN.includes(run.status) && (
        <ReportDownload organizationId={organizationId} runId={runId} />
      )}

      {run.status === "completed" && (
        <ExploitationFires organizationId={organizationId} runId={runId} />
      )}
    </div>
  );
}
