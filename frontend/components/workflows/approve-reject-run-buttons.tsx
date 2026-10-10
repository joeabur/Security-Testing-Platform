"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { WorkflowRun } from "@/lib/types";

/**
 * Resumes or ends a run paused by an unattended trigger (Celery Beat or the
 * inbound webhook) whose plan would queue a scan-touching action — already
 * reachable from `kervy workflow approve`/`reject`. Only ever rendered for a
 * run still in `awaiting_approval`; the backend re-checks that state itself
 * and answers 409 if it changed underneath this click (another approver, or
 * the run timing out), surfaced here as an ordinary error message rather
 * than a crash.
 *
 * Approve fires immediately — this codebase's existing lowest-friction
 * precedent (`run-workflow-button.tsx`). Reject requires a non-empty reason
 * first (the backend enforces 1-500 chars either way), so the friction of
 * typing one stands in for the confirmation dialog other breaking actions
 * use instead.
 */
export function ApproveRejectRunButtons({
  organizationId,
  workflowId,
  run,
}: {
  organizationId: string;
  workflowId: string;
  run: WorkflowRun;
}) {
  const router = useRouter();
  const [isApproving, setIsApproving] = useState(false);
  const [isRejecting, setIsRejecting] = useState(false);
  const [isRejectOpen, setIsRejectOpen] = useState(false);
  const [rejectReason, setRejectReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  const basePath = `/organizations/${organizationId}/workflows/${workflowId}/runs/${run.id}`;

  async function onApprove() {
    setIsApproving(true);
    setError(null);
    try {
      await clientApiFetch(`${basePath}/approve`, { method: "POST", body: JSON.stringify({}) });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setIsApproving(false);
    }
  }

  async function onReject() {
    setIsRejecting(true);
    setError(null);
    try {
      await clientApiFetch(`${basePath}/reject`, {
        method: "POST",
        body: JSON.stringify({ reason: rejectReason }),
      });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setIsRejecting(false);
    }
  }

  if (isRejectOpen) {
    return (
      <div className="flex w-full max-w-sm flex-col gap-2">
        <Textarea
          value={rejectReason}
          onChange={(event) => setRejectReason(event.target.value)}
          placeholder="Why is this run being rejected?"
          maxLength={500}
          aria-label="Rejection reason"
        />
        <div className="flex items-center gap-2">
          <Button
            type="button"
            size="sm"
            variant="destructive"
            onClick={onReject}
            isLoading={isRejecting}
            disabled={rejectReason.trim().length === 0}
          >
            {isRejecting ? "Rejecting..." : "Confirm reject"}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => {
              setIsRejectOpen(false);
              setRejectReason("");
            }}
          >
            Cancel
          </Button>
        </div>
        {error && (
          <p className="text-xs text-destructive" role="alert">
            {error}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col items-end gap-1.5">
      <div className="flex items-center gap-2">
        <Button type="button" size="sm" onClick={onApprove} isLoading={isApproving}>
          {isApproving ? "Approving..." : "Approve"}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="destructive"
          onClick={() => setIsRejectOpen(true)}
        >
          Reject
        </Button>
      </div>
      {error && (
        <p className="max-w-[16rem] text-right text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
