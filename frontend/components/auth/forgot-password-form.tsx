"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { clientApiFetch } from "@/lib/api-client";
import {
  forgotPasswordSchema,
  type ForgotPasswordInput,
} from "@/lib/validation";

export function ForgotPasswordForm() {
  const [submitted, setSubmitted] = useState(false);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ForgotPasswordInput>({
    resolver: zodResolver(forgotPasswordSchema),
  });

  async function onSubmit(values: ForgotPasswordInput) {
    // No error branch: the backend answers 202 unconditionally (never
    // disclosing whether the address is registered), so there is nothing to
    // distinguish here — a network failure aside, this form always ends in
    // the same confirmation state.
    await clientApiFetch("/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify(values),
    }).catch(() => undefined);
    setSubmitted(true);
  }

  if (submitted) {
    return (
      <div className="flex flex-col gap-4">
        <Alert tone="success">
          If an account with that email exists, a password reset link is on its
          way. Check your inbox.
        </Alert>
        <p className="text-center text-sm text-muted-foreground">
          <Link
            href="/login"
            className="font-medium text-primary hover:underline"
          >
            Back to sign in
          </Link>
        </p>
      </div>
    );
  }

  return (
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
      <Button type="submit" isLoading={isSubmitting}>
        {isSubmitting ? "Sending..." : "Send reset link"}
      </Button>
      <p className="text-center text-sm text-muted-foreground">
        <Link
          href="/login"
          className="font-medium text-primary hover:underline"
        >
          Back to sign in
        </Link>
      </p>
    </form>
  );
}
