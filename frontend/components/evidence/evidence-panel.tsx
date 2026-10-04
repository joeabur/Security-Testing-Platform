"use client";

import { useState } from "react";
import { ShieldCheck } from "lucide-react";

import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { clientApiDownload, clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { EvidenceManifestEntry, EvidenceVerification } from "@/lib/types";

/**
 * The evidence manifest for a run, and a button that re-checks the hash
 * chain and every bundle's content against its digest — the same two
 * things `kervy evidence list`/`kervy evidence verify` already expose,
 * now in the dashboard. Fetched on demand rather than polled: unlike run
 * status, a completed run's evidence does not change underneath a reader.
 */
export function EvidencePanel({
  organizationId,
  runId,
}: {
  organizationId: string;
  runId: string;
}) {
  const [entries, setEntries] = useState<EvidenceManifestEntry[] | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [verification, setVerification] = useState<EvidenceVerification | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloadingDigest, setDownloadingDigest] = useState<string | null>(null);

  async function onLoad() {
    setIsLoading(true);
    setListError(null);
    try {
      const manifest = await clientApiFetch<EvidenceManifestEntry[]>(
        `/organizations/${organizationId}/runs/${runId}/evidence`,
      );
      setEntries(manifest);
    } catch (error) {
      setListError(error instanceof ApiError ? error.message : "Could not load the manifest.");
    } finally {
      setIsLoading(false);
    }
  }

  async function onVerify() {
    setIsVerifying(true);
    setVerifyError(null);
    try {
      const result = await clientApiFetch<EvidenceVerification>(
        `/organizations/${organizationId}/runs/${runId}/evidence/verify`,
      );
      setVerification(result);
    } catch (error) {
      setVerifyError(error instanceof ApiError ? error.message : "Could not verify the chain.");
    } finally {
      setIsVerifying(false);
    }
  }

  async function onDownload(digest: string) {
    setDownloadingDigest(digest);
    setDownloadError(null);
    try {
      const { blob, filename } = await clientApiDownload(
        `/organizations/${organizationId}/runs/${runId}/evidence/${encodeURIComponent(digest)}`,
      );
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      setDownloadError(
        error instanceof ApiError
          ? error.message
          : "Could not download the bundle. Try again.",
      );
    } finally {
      setDownloadingDigest(null);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
          <CardTitle>Evidence</CardTitle>
        </div>
        <CardDescription>
          Every bundle this run wrote, hash-chained so a later edit cannot slip in unnoticed.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" size="sm" variant="outline" onClick={onLoad} isLoading={isLoading}>
            {entries === null ? (isLoading ? "Loading..." : "Load manifest") : "Reload manifest"}
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={onVerify} isLoading={isVerifying}>
            {isVerifying ? "Verifying..." : "Verify chain"}
          </Button>
          {verification && (
            <Badge tone={verification.ok ? "success" : "destructive"}>
              {verification.ok
                ? `Chain intact (${verification.entries} entries)`
                : `${verification.problems.length} problem(s)`}
            </Badge>
          )}
        </div>

        {listError && <Alert tone="destructive">{listError}</Alert>}
        {verifyError && <Alert tone="destructive">{verifyError}</Alert>}
        {downloadError && <Alert tone="destructive">{downloadError}</Alert>}
        {verification && !verification.ok && verification.problems.length > 0 && (
          <ul className="flex flex-col gap-1 text-sm text-destructive">
            {verification.problems.map((problem, index) => (
              <li key={index}>{problem}</li>
            ))}
          </ul>
        )}

        {entries !== null && (
          entries.length === 0 ? (
            <p className="text-sm text-muted-foreground">No evidence was recorded for this run.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-border text-xs uppercase tracking-wide text-muted-foreground">
                    <th className="py-1.5 pr-3">#</th>
                    <th className="py-1.5 pr-3">Probe</th>
                    <th className="py-1.5 pr-3">Digest</th>
                    <th className="py-1.5 pr-3">Recorded</th>
                    <th className="py-1.5" />
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry) => (
                    <tr key={entry.sequence} className="border-b border-border last:border-0">
                      <td className="py-1.5 pr-3 align-top">{entry.sequence}</td>
                      <td className="py-1.5 pr-3 align-top">{entry.probe_id}</td>
                      <td className="py-1.5 pr-3 align-top">
                        <code className="text-xs">{entry.digest.slice(0, 23)}…</code>
                      </td>
                      <td className="py-1.5 pr-3 align-top text-muted-foreground">
                        {new Date(entry.created_at).toLocaleString()}
                      </td>
                      <td className="py-1.5 align-top">
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => onDownload(entry.digest)}
                          isLoading={downloadingDigest === entry.digest}
                        >
                          Download
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        )}
      </CardContent>
    </Card>
  );
}
