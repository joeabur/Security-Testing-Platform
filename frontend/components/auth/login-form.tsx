"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { OAuthProviders, TotpChallenge, User } from "@/lib/types";
import { loginSchema, type LoginInput } from "@/lib/validation";

import { OAuthButtons } from "./oauth-buttons";
import { TotpChallengeForm } from "./totp-challenge-form";

// Matches the `oauth_error` codes app/api/v1/routers/auth.py's callback
// redirects with — kept as a lookup with a fallback rather than echoing the
// code, so an unrecognized future value still reads as a sentence.
const OAUTH_ERROR_MESSAGES: Record<string, string> = {
  provider_denied: "Sign-in was cancelled.",
  missing_code_or_state: "Sign-in did not complete. Try again.",
  invalid_state: "That sign-in link expired. Try again.",
  service_unavailable: "Sign-in is temporarily unavailable. Try again shortly.",
  exchange_failed: "Sign-in did not complete. Try again.",
  account_inactive: "This account is inactive.",
  account_missing: "Sign-in did not complete. Try again.",
  email_already_registered:
    "An account with that email already exists. Sign in with your password instead.",
};

export function LoginForm({
  providers,
  oauthError,
}: {
  providers: OAuthProviders;
  oauthError?: string;
}) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(
    oauthError
      ? (OAUTH_ERROR_MESSAGES[oauthError] ??
          "Sign-in did not complete. Try again.")
      : null,
  );
  // Set only when `POST /auth/login` answers with a `TotpChallenge` instead
  // of a session — the account has 2FA enabled, and the password was
  // already correct (that is exactly what earns a challenge instead of a
  // 401). The rest of this form's own state is left alone underneath so
  // "Back to sign in" doesn't lose what was typed.
  const [challenge, setChallenge] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginInput>({ resolver: zodResolver(loginSchema) });

  async function onSubmit(values: LoginInput) {
    setFormError(null);
    try {
      const result = await clientApiFetch<{ user: User } | TotpChallenge>("/auth/login", {
        method: "POST",
        body: JSON.stringify(values),
      });
      if ("requires_totp" in result) {
        setChallenge(result.challenge);
        return;
      }
      router.push("/dashboard");
      router.refresh();
    } catch (error) {
      setFormError(
        error instanceof ApiError
          ? error.message
          : "Something went wrong. Try again.",
      );
    }
  }

  if (challenge) {
    return <TotpChallengeForm challenge={challenge} onBack={() => setChallenge(null)} />;
  }

  return (
    <div className="flex flex-col gap-4">
      <OAuthButtons providers={providers} />
      <form
        onSubmit={handleSubmit(onSubmit)}
        noValidate
        className="flex flex-col gap-4"
      >
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="email">Email</Label>
          <Input
            id="email"
            type="email"
            autoComplete="email"
            aria-invalid={!!errors.email}
            {...register("email")}
          />
          {errors.email && (
            <p className="text-sm text-destructive" role="alert">
              {errors.email.message}
            </p>
          )}
        </div>
        <div className="flex flex-col gap-1.5">
          <div className="flex items-center justify-between">
            <Label htmlFor="password">Password</Label>
            <Link
              href="/forgot-password"
              className="text-xs font-medium text-primary hover:underline"
            >
              Forgot password?
            </Link>
          </div>
          <Input
            id="password"
            type="password"
            autoComplete="current-password"
            aria-invalid={!!errors.password}
            {...register("password")}
          />
          {errors.password && (
            <p className="text-sm text-destructive" role="alert">
              {errors.password.message}
            </p>
          )}
        </div>
        {formError && <Alert tone="destructive">{formError}</Alert>}
        <Button type="submit" isLoading={isSubmitting}>
          {isSubmitting ? "Signing in..." : "Sign in"}
        </Button>
        <p className="text-center text-sm text-muted-foreground">
          Need an account?{" "}
          <Link
            href="/register"
            className="font-medium text-primary hover:underline"
          >
            Register
          </Link>
        </p>
      </form>
    </div>
  );
}
