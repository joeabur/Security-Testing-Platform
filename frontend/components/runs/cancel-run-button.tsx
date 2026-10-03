"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { Run } from "@/lib/types";

export function CancelRunButton({
  organizationId,
  runId,
}: {
  organizationId: string;
  runId: string;
}) {
  const router = useRouter();
  const [isCancelling, setIsCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onCancel() {
    setIsCancelling(true);
    setError(null);
    try {
      await clientApiFetch<Run>(`/organizations/${organizationId}/runs/${runId}/cancel`, {
        method: "POST",
      });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setIsCancelling(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <Button
        type="button"
        size="sm"
        variant="destructive"
        onClick={onCancel}
        isLoading={isCancelling}
      >
        {isCancelling ? "Cancelling..." : "Cancel run"}
      </Button>
      {error && (
        <p className="max-w-[16rem] text-right text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
