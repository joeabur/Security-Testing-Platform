"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";

export function RevokeInvitationButton({
  organizationId,
  invitationId,
  email,
}: {
  organizationId: string;
  invitationId: string;
  email: string;
}) {
  const router = useRouter();
  const [isRevoking, setIsRevoking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onRevoke() {
    if (!window.confirm(`Revoke the pending invitation for ${email}?`)) {
      return;
    }
    setIsRevoking(true);
    setError(null);
    try {
      await clientApiFetch(`/organizations/${organizationId}/invitations/${invitationId}`, {
        method: "DELETE",
      });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setIsRevoking(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Button type="button" size="sm" variant="outline" onClick={onRevoke} isLoading={isRevoking}>
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
