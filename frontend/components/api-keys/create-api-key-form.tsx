"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { CheckCircle2 } from "lucide-react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { ApiKeyCreated } from "@/lib/types";
import { createApiKeySchema, type CreateApiKeyInput } from "@/lib/validation";

const SCOPES: { value: "read" | "triage" | "scan"; label: string; hint: string }[] = [
  { value: "read", label: "Read", hint: "View targets, runs, and findings" },
  { value: "triage", label: "Triage", hint: "Also update finding status and remediation" },
  { value: "scan", label: "Scan", hint: "Also start runs against an authorized target" },
];

/**
 * Create an API key — already reachable from `kervy apikey create`, missing
 * from the dashboard until now. There is deliberately no role picker: the
 * effective role is derived server-side from the chosen scopes
 * (`role_for_scopes` in app/models/api_key.py), capped at security engineer,
 * so a credential in a CI runner can never reach what a human grant can.
 * The token is returned exactly once in the create response and shown here
 * the same way `RotateWebhookSecretButton`/`RecoveryCodesDisplay` show a
 * one-time secret — never stored, never retrievable again afterward.
 */
export function CreateApiKeyForm({ organizationId }: { organizationId: string }) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateApiKeyInput>({
    resolver: zodResolver(createApiKeySchema),
    defaultValues: { name: "", scopes: [], expires_at: "" },
  });

  useEffect(() => {
    if (!copied) {
      return;
    }
    const timeout = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(timeout);
  }, [copied]);

  async function onSubmit(values: CreateApiKeyInput) {
    setFormError(null);
    try {
      const key = await clientApiFetch<ApiKeyCreated>(`/organizations/${organizationId}/api-keys`, {
        method: "POST",
        body: JSON.stringify({
          name: values.name,
          scopes: values.scopes,
          expires_at: values.expires_at ? new Date(values.expires_at).toISOString() : null,
        }),
      });
      setCreated(key);
      reset();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  async function copyToken() {
    if (!created) {
      return;
    }
    try {
      await navigator.clipboard.writeText(created.token);
      setCopied(true);
    } catch {
      // Clipboard access can be denied by the browser; the token is still
      // fully visible and selectable on the page either way.
    }
  }

  function onDone() {
    setCreated(null);
    router.refresh();
  }

  if (created) {
    return (
      <div className="flex w-full flex-col gap-3 rounded-lg border border-border bg-muted/40 p-4">
        <p className="text-sm">
          API key <strong className="text-foreground">{created.name}</strong> created.{" "}
          <strong className="text-foreground">The token will not be shown again.</strong>
        </p>
        <code className="block overflow-x-auto rounded-md border border-border bg-background px-3 py-2 font-mono text-sm">
          {created.token}
        </code>
        <div className="flex gap-2">
          <Button type="button" size="sm" variant="outline" onClick={copyToken}>
            {copied ? (
              <>
                <CheckCircle2 className="h-4 w-4" aria-hidden />
                Copied
              </>
            ) : (
              "Copy token"
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
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="apikey-name">Name</Label>
        <Input id="apikey-name" placeholder="e.g. CI pipeline" {...register("name")} />
        {errors.name && (
          <p className="text-sm text-destructive" role="alert">
            {errors.name.message}
          </p>
        )}
      </div>
      <div className="flex flex-col gap-1.5">
        <Label>Scopes</Label>
        <div className="flex flex-col gap-2">
          {SCOPES.map((scope) => (
            <div key={scope.value} className="flex items-center gap-2">
              <Checkbox
                id={`apikey-scope-${scope.value}`}
                value={scope.value}
                {...register("scopes")}
              />
              <Label htmlFor={`apikey-scope-${scope.value}`} className="font-normal">
                {scope.label} <span className="text-muted-foreground">— {scope.hint}</span>
              </Label>
            </div>
          ))}
        </div>
        {errors.scopes && (
          <p className="text-sm text-destructive" role="alert">
            {errors.scopes.message}
          </p>
        )}
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="apikey-expires">Expires (optional)</Label>
        <Input id="apikey-expires" type="datetime-local" {...register("expires_at")} />
      </div>
      {formError && <Alert tone="destructive">{formError}</Alert>}
      <Button type="submit" isLoading={isSubmitting} className="self-start">
        {isSubmitting ? "Creating..." : "Create API key"}
      </Button>
    </form>
  );
}
