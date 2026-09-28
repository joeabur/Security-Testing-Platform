"use client";

import { useEffect, useState } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { clientApiFetch } from "@/lib/api-client";
import { TERMINAL_RUN_STATUSES, type Run, type RunEvent } from "@/lib/types";

const POLL_MS = 2000;

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

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>
            Run status: <span className="font-mono">{run.status}</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-2 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-muted-foreground">Checks</dt>
              <dd>
                {run.checks_completed}/{run.checks_total}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Requests used</dt>
              <dd>{run.requests_used}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Requests blocked</dt>
              <dd>{run.requests_blocked}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Findings</dt>
              <dd>{run.findings_reported}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Profile</dt>
              <dd>{run.profile}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Safe mode</dt>
              <dd>{run.safe_mode ? "On" : "Off"}</dd>
            </div>
          </dl>
          {run.halted_reason && (
            <p className="mt-4 text-sm text-destructive">Halted: {run.halted_reason}</p>
          )}
          {run.error_message && (
            <p className="mt-4 text-sm text-destructive">Error: {run.error_message}</p>
          )}
          {!TERMINAL_RUN_STATUSES.includes(run.status) && (
            <p className="mt-4 text-xs text-muted-foreground">Updating every few seconds…</p>
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
            <ul className="flex flex-col gap-2 text-sm">
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
    </div>
  );
}
