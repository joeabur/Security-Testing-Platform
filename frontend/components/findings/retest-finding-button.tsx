"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
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
  const [isConfirmed, setIsConfirmed] = useState(false);
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
          authorization_confirmed: isConfirmed,
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
    <div className="flex flex-col items-start gap-2">
      <div className="flex items-start gap-2">
        <Checkbox
          id={`retest-authorized-${findingId}`}
          className="mt-0.5"
          checked={isConfirmed}
          onChange={(event) => setIsConfirmed(event.target.checked)}
        />
        <Label htmlFor={`retest-authorized-${findingId}`} className="font-normal">
          I confirm this retest is authorized for this target.
        </Label>
      </div>
      <Button
        type="button"
        size="sm"
        variant="outline"
        onClick={onRetest}
        isLoading={isStarting}
        disabled={!isConfirmed}
      >
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
