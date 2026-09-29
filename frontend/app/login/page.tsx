import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { ShieldCheck } from "lucide-react";

import { LoginForm } from "@/components/auth/login-form";
import { ThemeToggle } from "@/components/nav/theme-toggle";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { isAuthenticated, serverApiFetch } from "@/lib/api-server";
import type { OAuthProviders } from "@/lib/types";

export const metadata: Metadata = { title: "Sign in — Kervy Security" };

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ oauth_error?: string }>;
}) {
  if (await isAuthenticated()) {
    redirect("/dashboard");
  }

  // Unauthenticated GET, so this never throws for a caller with no session —
  // still guarded, since a provider outage or a misconfigured backend should
  // degrade to "no OAuth buttons" rather than break the whole login page.
  const providers = await serverApiFetch<OAuthProviders>(
    "/auth/oauth/providers",
  ).catch(() => ({ google: false, github: false }) satisfies OAuthProviders);
  const { oauth_error: oauthError } = await searchParams;

  return (
    <main className="bg-hero-fade relative flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-12">
      <div className="absolute right-4 top-4">
        <ThemeToggle />
      </div>
      <div className="flex animate-fade-up items-center gap-2 text-foreground">
        <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-elevated">
          <ShieldCheck className="h-5 w-5" aria-hidden />
        </span>
        <span className="text-xl font-semibold tracking-tight">
          Kervy Security
        </span>
      </div>
      <Card className="w-full max-w-sm animate-fade-up shadow-elevated">
        <CardHeader>
          <CardTitle>Sign in</CardTitle>
          <CardDescription>
            Access your organization&apos;s assessments and findings.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <LoginForm providers={providers} oauthError={oauthError} />
        </CardContent>
      </Card>
    </main>
  );
}
