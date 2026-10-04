"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";

export function RemoveMemberButton({
  organizationId,
  memberId,
  email,
}: {
  organizationId: string;
  memberId: string;
  email: string;
}) {
  const router = useRouter();
  const [isRemoving, setIsRemoving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onRemove() {
    if (!window.confirm(`Remove ${email} from this organization?`)) {
      return;
    }
    setIsRemoving(true);
    setError(null);
    try {
      await clientApiFetch(`/organizations/${organizationId}/members/${memberId}`, {
        method: "DELETE",
      });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setIsRemoving(false);
    }
  }

  return (
    <div className="flex items-center gap-2">
      <Button type="button" size="sm" variant="destructive" onClick={onRemove} isLoading={isRemoving}>
        {isRemoving ? "Removing..." : "Remove"}
      </Button>
      {error && (
        <span className="text-xs text-destructive" role="alert">
          {error}
        </span>
      )}
    </div>
  );
}
