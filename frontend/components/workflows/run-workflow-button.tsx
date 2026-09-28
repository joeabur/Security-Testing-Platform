"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { WorkflowRun } from "@/lib/types";

export function RunWorkflowButton({
  organizationId,
  workflowId,
}: {
  organizationId: string;
  workflowId: string;
}) {
  const router = useRouter();
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<WorkflowRun | null>(null);

  async function onRun() {
    setIsRunning(true);
    setError(null);
    try {
      const run = await clientApiFetch<WorkflowRun>(
        `/organizations/${organizationId}/workflows/${workflowId}/runs`,
        { method: "POST", body: JSON.stringify({}) },
      );
      setLastResult(run);
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <Button type="button" size="sm" variant="outline" onClick={onRun} disabled={isRunning}>
        {isRunning ? "Running..." : "Run now"}
      </Button>
      {lastResult && (
        <p className="text-xs text-muted-foreground">
          Last trigger: {lastResult.status}
          {lastResult.gate_passed !== null && (lastResult.gate_passed ? " · gate passed" : " · gate failed")}
        </p>
      )}
      {error && (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
