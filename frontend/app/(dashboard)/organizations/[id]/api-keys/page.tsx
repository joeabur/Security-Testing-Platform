import type { Metadata } from "next";
import { KeyRound } from "lucide-react";

import { CreateApiKeyForm } from "@/components/api-keys/create-api-key-form";
import { RevokeApiKeyButton } from "@/components/api-keys/revoke-api-key-button";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { serverApiFetch } from "@/lib/api-server";
import { ApiError } from "@/lib/errors";
import type { ApiKey } from "@/lib/types";

export const metadata: Metadata = { title: "API keys — Kervy Security" };

function formatRole(role: string): string {
  return role
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export default async function ApiKeysPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  // Create/list/revoke are all Admin-only (same tier as everything else that
  // changes what a standing credential can do) — a lower-tier member
  // reaching this page by its own nav tab or a direct URL is expected, not
  // an error, same pattern `workflows/page.tsx` already uses for its own
  // higher-tier-only call.
  let keys: ApiKey[] = [];
  try {
    keys = await serverApiFetch<ApiKey[]>(`/organizations/${id}/api-keys`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      return (
        <div className="flex animate-fade-in flex-col gap-6">
          <Alert tone="warning">You need Admin access or higher to manage API keys.</Alert>
        </div>
      );
    }
    throw error;
  }

  return (
    <div className="flex animate-fade-in flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Create an API key</CardTitle>
          <CardDescription>
            For CI/CD and other automated callers. Rotation is create-then-revoke, not an
            in-place swap, so a pipeline can move onto the new key before the old one stops
            working.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <CreateApiKeyForm organizationId={id} />
        </CardContent>
      </Card>

      <div className="flex flex-col gap-3">
        <h2 className="text-lg font-semibold">API keys</h2>
        {keys.length === 0 ? (
          <Card className="border-dashed shadow-none">
            <CardHeader className="items-center py-10 text-center">
              <span className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
                <KeyRound className="h-6 w-6" aria-hidden />
              </span>
              <CardDescription className="mt-1">No API keys yet.</CardDescription>
            </CardHeader>
          </Card>
        ) : (
          keys.map((key) => (
            <Card key={key.id} className="transition-shadow duration-150 hover:shadow-elevated">
              <CardContent className="flex flex-wrap items-center justify-between gap-4 py-4">
                <div>
                  <p className="font-medium">{key.name}</p>
                  <p className="text-sm text-muted-foreground">
                    {key.key_id} · acts as {formatRole(key.role)}
                  </p>
                  <div className="mt-2 flex flex-wrap items-center gap-1.5">
                    {key.scopes.map((scope) => (
                      <Badge key={scope} tone="primary">
                        {scope}
                      </Badge>
                    ))}
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">
                    Created {new Date(key.created_at).toLocaleDateString()}
                    {key.expires_at && ` · expires ${new Date(key.expires_at).toLocaleDateString()}`}
                    {key.last_used_at &&
                      ` · last used ${new Date(key.last_used_at).toLocaleDateString()}`}
                  </p>
                </div>
                <RevokeApiKeyButton organizationId={id} apiKey={key} />
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
