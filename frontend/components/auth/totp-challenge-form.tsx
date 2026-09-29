"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { User } from "@/lib/types";
import { totpCodeSchema, type TotpCodeInput } from "@/lib/validation";

/**
 * The second step of login once `POST /auth/login` has returned a
 * `TotpChallenge` instead of a session (`app/api/v1/routers/auth.py`'s
 * `login()`). `challenge` is a short-lived, single-use ticket — redeeming
 * it twice (a double-submit, or going back and retrying) gets a fresh 401
 * from the backend's own replay guard, handled below by sending the user
 * back to re-enter their password rather than retrying with a dead ticket.
 */
export function TotpChallengeForm({
  challenge,
  onBack,
}: {
  challenge: string;
  onBack: () => void;
}) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<TotpCodeInput>({ resolver: zodResolver(totpCodeSchema) });

  async function onSubmit(values: TotpCodeInput) {
    setFormError(null);
    try {
      await clientApiFetch<{ user: User }>("/auth/login/2fa", {
        method: "POST",
        body: JSON.stringify({ challenge, code: values.code.trim() }),
      });
      router.push("/dashboard");
      router.refresh();
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        setFormError("That code is incorrect, or this sign-in attempt has expired. Sign in again.");
      } else if (error instanceof ApiError && error.status === 429) {
        setFormError("Too many attempts. Wait a moment and try again.");
      } else {
        setFormError("Something went wrong. Try again.");
      }
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold tracking-tight">Two-factor authentication</h2>
        <p className="text-sm text-muted-foreground">
          Enter the 6-digit code from your authenticator app, or one of your recovery codes.
        </p>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="code">Authentication code</Label>
        <Input
          id="code"
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          autoFocus
          placeholder="123456"
          aria-invalid={!!errors.code}
          {...register("code")}
        />
        {errors.code && (
          <p className="text-sm text-destructive" role="alert">
            {errors.code.message}
          </p>
        )}
      </div>
      {formError && <Alert tone="destructive">{formError}</Alert>}
      <Button type="submit" isLoading={isSubmitting}>
        {isSubmitting ? "Verifying..." : "Verify"}
      </Button>
      <Button type="button" variant="ghost" size="sm" onClick={onBack}>
        Back to sign in
      </Button>
    </form>
  );
}
