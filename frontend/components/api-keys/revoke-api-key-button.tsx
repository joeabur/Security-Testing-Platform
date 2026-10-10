"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { ApiKey } from "@/lib/types";

export function RevokeApiKeyButton({
  organizationId,
  apiKey,
}: {
  organizationId: string;
  apiKey: ApiKey;
}) {
  const router = useRouter();
  const [isRevoking, setIsRevoking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onRevoke() {
    if (
      !window.confirm(
        `Revoke the API key "${apiKey.name}"? Anything using it will stop working immediately.`,
      )
    ) {
      return;
    }
    setIsRevoking(true);
    setError(null);
    try {
      await clientApiFetch(`/organizations/${organizationId}/api-keys/${apiKey.id}/revoke`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setIsRevoking(false);
    }
  }

  if (apiKey.revoked_at) {
    return <span className="text-xs text-muted-foreground">Revoked</span>;
  }

  return (
    <div className="flex items-center gap-2">
      <Button type="button" size="sm" variant="destructive" onClick={onRevoke} isLoading={isRevoking}>
        {isRevoking ? "Revoking..." : "Revoke"}
      </Button>
      {error && (
        <span className="text-xs text-destructive" role="alert">
          {error}
        </span>
      )}
    </div>
  );
}
