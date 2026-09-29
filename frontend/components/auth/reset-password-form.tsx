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
import { resetPasswordSchema, type ResetPasswordInput } from "@/lib/validation";

export function ResetPasswordForm({ token }: { token?: string }) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ResetPasswordInput>({
    resolver: zodResolver(resetPasswordSchema),
  });

  async function onSubmit(values: ResetPasswordInput) {
    if (!token) {
      return;
    }
    setFormError(null);
    try {
      // The backend deliberately does not start a session on a successful
      // reset (app/api/v1/routers/auth.py::reset_password's docstring): the
      // caller has proven control of an inbox, not yet a browser worth
      // trusting with a cookie. Sign in with the new password from here.
      await clientApiFetch("/auth/reset-password", {
        method: "POST",
        body: JSON.stringify({ token, new_password: values.new_password }),
      });
      router.push("/login");
    } catch (error) {
      setFormError(
        error instanceof ApiError
          ? "That reset link is invalid or has expired. Request a new one."
          : "Something went wrong. Try again.",
      );
    }
  }

  if (!token) {
    return (
      <Alert tone="destructive">
        This reset link is missing its token.{" "}
        <Link href="/forgot-password" className="font-medium underline">
          Request a new one
        </Link>
        .
      </Alert>
    );
  }

  return (
    <form
      onSubmit={handleSubmit(onSubmit)}
      noValidate
      className="flex flex-col gap-4"
    >
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="new_password">New password</Label>
        <Input
          id="new_password"
          type="password"
          autoComplete="new-password"
          aria-invalid={!!errors.new_password}
          {...register("new_password")}
        />
        {errors.new_password ? (
          <p className="text-sm text-destructive" role="alert">
            {errors.new_password.message}
          </p>
        ) : (
          <p className="text-sm text-muted-foreground">
            At least 12 characters.
          </p>
        )}
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="confirm_password">Confirm new password</Label>
        <Input
          id="confirm_password"
          type="password"
          autoComplete="new-password"
          aria-invalid={!!errors.confirm_password}
          {...register("confirm_password")}
        />
        {errors.confirm_password && (
          <p className="text-sm text-destructive" role="alert">
            {errors.confirm_password.message}
          </p>
        )}
      </div>
      {formError && <Alert tone="destructive">{formError}</Alert>}
      <Button type="submit" isLoading={isSubmitting}>
        {isSubmitting ? "Resetting..." : "Reset password"}
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
