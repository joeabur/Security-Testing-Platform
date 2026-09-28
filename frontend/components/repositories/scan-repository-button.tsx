"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";

interface ScanResult {
  run_id: string;
  status: string;
}

export function ScanRepositoryButton({
  organizationId,
  repositoryId,
}: {
  organizationId: string;
  repositoryId: string;
}) {
  const router = useRouter();
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onScan() {
    setIsScanning(true);
    setError(null);
    try {
      await clientApiFetch<ScanResult>(
        `/organizations/${organizationId}/repositories/${repositoryId}/scan`,
        { method: "POST", body: JSON.stringify({ safe_mode: true }) },
      );
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <Button type="button" size="sm" variant="outline" onClick={onScan} disabled={isScanning}>
        {isScanning ? "Starting scan..." : "Scan"}
      </Button>
      {error && (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
