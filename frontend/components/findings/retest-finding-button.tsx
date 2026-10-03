"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { Run } from "@/lib/types";

export function RetestFindingButton({
  organizationId,
  findingId,
  targetId,
}: {
  organizationId: string;
  findingId: string;
  targetId: string;
}) {
  const router = useRouter();
  const [isStarting, setIsStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onRetest() {
    setIsStarting(true);
    setError(null);
    try {
      const run = await clientApiFetch<Run>(`/organizations/${organizationId}/retests`, {
        method: "POST",
        body: JSON.stringify({
          target_id: targetId,
          finding_ids: [findingId],
          authorization_confirmed: true,
        }),
      });
      router.push(`/organizations/${organizationId}/runs/${run.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setIsStarting(false);
    }
  }

  return (
    <div className="flex flex-col items-start gap-1">
      <Button type="button" size="sm" variant="outline" onClick={onRetest} isLoading={isStarting}>
        {isStarting ? "Starting retest..." : "Retest this finding"}
      </Button>
      {error && (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
