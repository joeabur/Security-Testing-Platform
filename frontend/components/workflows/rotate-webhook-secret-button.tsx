"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { CheckCircle2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";

interface WebhookSecretReveal {
  secret: string;
  webhook_url: string;
}

/**
 * Rotates a workflow's inbound webhook secret — already reachable from
 * `kervy workflow webhook-secret`, missing from the dashboard until now.
 * Confirmed first: rotating invalidates whatever secret a live sender is
 * currently using, the same "breaks a live credential" class of action
 * `remove-member-button.tsx`/`revoke-invitation-button.tsx` already guard
 * with `window.confirm`. The new secret is shown exactly once, the same
 * discipline `RecoveryCodesDisplay` (two-factor-settings.tsx) follows for
 * recovery codes — never stored here, never retrievable again afterward.
 */
export function RotateWebhookSecretButton({
  organizationId,
  workflowId,
  workflowName,
}: {
  organizationId: string;
  workflowId: string;
  workflowName: string;
}) {
  const router = useRouter();
  const [isRotating, setIsRotating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reveal, setReveal] = useState<WebhookSecretReveal | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) {
      return;
    }
    const timeout = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(timeout);
  }, [copied]);

  async function onRotate() {
    if (
      !window.confirm(
        `Rotate the webhook secret for "${workflowName}"? Anything still sending webhooks ` +
          "with the old secret will stop being accepted immediately.",
      )
    ) {
      return;
    }
    setIsRotating(true);
    setError(null);
    try {
      const result = await clientApiFetch<WebhookSecretReveal>(
        `/organizations/${organizationId}/workflows/${workflowId}/webhook-secret`,
        { method: "POST", body: JSON.stringify({}) },
      );
      setReveal(result);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setIsRotating(false);
    }
  }

  async function copySecret() {
    if (!reveal) {
      return;
    }
    try {
      await navigator.clipboard.writeText(reveal.secret);
      setCopied(true);
    } catch {
      // Clipboard access can be denied by the browser; the secret is still
      // fully visible and selectable on the page either way.
    }
  }

  function onDone() {
    setReveal(null);
    router.refresh();
  }

  if (reveal) {
    return (
      <div className="flex w-full flex-col gap-3 rounded-lg border border-border bg-muted/40 p-4">
        <p className="text-sm">
          Webhook secret rotated.{" "}
          <strong className="text-foreground">It will not be shown again.</strong>
        </p>
        <div className="flex flex-col gap-1.5">
          <span className="text-xs text-muted-foreground">Secret</span>
          <code className="block overflow-x-auto rounded-md border border-border bg-background px-3 py-2 font-mono text-sm">
            {reveal.secret}
          </code>
        </div>
        <div className="flex flex-col gap-1.5">
          <span className="text-xs text-muted-foreground">Webhook URL</span>
          <code className="block overflow-x-auto rounded-md border border-border bg-background px-3 py-2 font-mono text-sm">
            {reveal.webhook_url}
          </code>
        </div>
        <div className="flex gap-2">
          <Button type="button" size="sm" variant="outline" onClick={copySecret}>
            {copied ? (
              <>
                <CheckCircle2 className="h-4 w-4" aria-hidden />
                Copied
              </>
            ) : (
              "Copy secret"
            )}
          </Button>
          <Button type="button" size="sm" onClick={onDone}>
            Done
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-end gap-1.5">
      <Button type="button" size="sm" variant="outline" onClick={onRotate} isLoading={isRotating}>
        {isRotating ? "Rotating..." : "Rotate webhook secret"}
      </Button>
      {error && (
        <p className="max-w-[16rem] text-right text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
