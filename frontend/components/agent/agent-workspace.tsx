"use client";

import { useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { clientApiFetch } from "@/lib/api-client";
import { cn } from "@/lib/cn";
import { ApiError } from "@/lib/errors";
import type { AgentToolCatalogEntry, Investigation, StepOutcome } from "@/lib/types";

const POLL_MS = 2000;

const RISK_LABEL: Record<string, string> = {
  read_only: "Read-only",
  standard: "Standard",
  sensitive: "Sensitive — needs approval",
};

export function AgentWorkspace({
  organizationId,
  tools,
}: {
  organizationId: string;
  tools: AgentToolCatalogEntry[];
}) {
  const [request, setRequest] = useState("");
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isActing, setIsActing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Not persisted anywhere — see the page's own note. This is the entire
  // "conversation": one investigation at a time, gone on reload.
  const pollTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    return () => {
      if (pollTimer.current) clearTimeout(pollTimer.current);
    };
  }, []);

  function schedulePoll(investigationId: string) {
    if (pollTimer.current) clearTimeout(pollTimer.current);
    pollTimer.current = setTimeout(async () => {
      try {
        const latest = await clientApiFetch<Investigation>(
          `/organizations/${organizationId}/agent/investigate/${investigationId}/status`,
        );
        setInvestigation(latest);
        if (latest.status === "awaiting_approval") {
          schedulePoll(investigationId);
        }
      } catch {
        // A 404 here just means someone else already resolved it (approved
        // or cancelled it); leave the last-known state on screen rather
        // than replacing it with an error for a normal outcome.
      }
    }, POLL_MS);
  }

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!request.trim()) return;
    setIsSubmitting(true);
    setError(null);
    try {
      const result = await clientApiFetch<Investigation>(
        `/organizations/${organizationId}/agent/investigate`,
        { method: "POST", body: JSON.stringify({ request }) },
      );
      setInvestigation(result);
      setRequest("");
      if (result.status === "awaiting_approval") {
        schedulePoll(result.investigation_id);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setIsSubmitting(false);
    }
  }

  async function onApprove() {
    if (!investigation) return;
    setIsActing(true);
    setError(null);
    try {
      const result = await clientApiFetch<Investigation>(
        `/organizations/${organizationId}/agent/investigate/${investigation.investigation_id}/approve`,
        { method: "POST", body: JSON.stringify({}) },
      );
      setInvestigation(result);
      if (result.status === "awaiting_approval") {
        schedulePoll(result.investigation_id);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not approve this step.");
    } finally {
      setIsActing(false);
    }
  }

  async function onCancel() {
    if (!investigation) return;
    setIsActing(true);
    setError(null);
    try {
      await clientApiFetch<void>(
        `/organizations/${organizationId}/agent/investigate/${investigation.investigation_id}/cancel`,
        { method: "POST" },
      );
      setInvestigation({ ...investigation, status: "cancelled", pending_approval: null });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not cancel this investigation.");
    } finally {
      setIsActing(false);
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
      <div className="flex flex-col gap-4">
        <Card>
          <CardContent className="pt-6">
            <form onSubmit={onSubmit} className="flex flex-col gap-3">
              <Textarea
                value={request}
                onChange={(event) => setRequest(event.target.value)}
                placeholder="e.g. List my authorized targets, or summarize the last scan of acme-api"
                rows={3}
                disabled={isSubmitting}
              />
              {error && (
                <p className="text-sm text-destructive" role="alert">
                  {error}
                </p>
              )}
              <Button type="submit" disabled={isSubmitting || !request.trim()} className="self-start">
                {isSubmitting ? "Thinking..." : "Ask the agent"}
              </Button>
            </form>
          </CardContent>
        </Card>

        {investigation && (
          <InvestigationView
            investigation={investigation}
            isActing={isActing}
            onApprove={onApprove}
            onCancel={onCancel}
          />
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Available tools</CardTitle>
          <CardDescription>
            What the agent may call, and the minimum role each one requires.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="flex flex-col gap-3 text-sm">
            {tools.map((tool) => (
              <li key={tool.name} className="border-b border-border pb-3 last:border-0 last:pb-0">
                <p className="font-mono text-xs font-medium">{tool.name}</p>
                <p className="text-muted-foreground">{tool.description}</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {RISK_LABEL[tool.risk_level] ?? tool.risk_level} · role: {tool.minimum_role}
                </p>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

function InvestigationView({
  investigation,
  isActing,
  onApprove,
  onCancel,
}: {
  investigation: Investigation;
  isActing: boolean;
  onApprove: () => void;
  onCancel: () => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Status: <span className="font-mono">{investigation.status}</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {investigation.status === "awaiting_approval" && investigation.pending_approval && (
          <div className="rounded-md border border-border bg-muted p-4">
            <p className="text-sm font-medium">
              Approval needed:{" "}
              <span className="font-mono">{investigation.pending_approval.tool_name}</span>
            </p>
            <p className="text-sm text-muted-foreground">
              {investigation.pending_approval.description}
            </p>
            <div className="mt-3 flex gap-2">
              <Button type="button" size="sm" onClick={onApprove} disabled={isActing}>
                {isActing ? "Working..." : "Approve"}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={onCancel}
                disabled={isActing}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}

        {investigation.outcomes.length > 0 && (
          <ol className="flex flex-col gap-2 text-sm">
            {investigation.outcomes.map((outcome, index) => (
              <StepRow key={`${outcome.tool_name}-${index}`} outcome={outcome} />
            ))}
          </ol>
        )}

        {investigation.summary && (
          <div>
            <p className="text-sm font-medium">Summary</p>
            <p className="whitespace-pre-wrap text-sm text-muted-foreground">
              {investigation.summary}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function StepRow({ outcome }: { outcome: StepOutcome }) {
  const ok = outcome.status === "ok";
  return (
    <li className="border-b border-border pb-2 last:border-0">
      <span className="font-mono text-xs">{outcome.tool_name}</span>{" "}
      <span className={cn("text-xs font-medium", ok ? "text-primary" : "text-destructive")}>
        {outcome.status}
      </span>
      {outcome.error && <p className="text-xs text-destructive">{outcome.error}</p>}
    </li>
  );
}
