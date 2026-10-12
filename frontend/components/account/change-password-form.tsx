"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { KeyRound } from "lucide-react";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import { changePasswordSchema, type ChangePasswordInput } from "@/lib/validation";

export function ChangePasswordForm() {
  const [formError, setFormError] = useState<string | null>(null);
  const [succeeded, setSucceeded] = useState(false);
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<ChangePasswordInput>({ resolver: zodResolver(changePasswordSchema) });

  async function onSubmit(values: ChangePasswordInput) {
    setFormError(null);
    setSucceeded(false);
    try {
      // The response carries a fresh access token and re-sets the session
      // cookie (app/api/v1/routers/auth.py::change_password) — this
      // browser's own session is replaced, not ended, so there is nothing
      // from the body this page needs to read or store itself.
      await clientApiFetch("/auth/change-password", {
        method: "POST",
        body: JSON.stringify({
          current_password: values.current_password,
          new_password: values.new_password,
        }),
      });
      setSucceeded(true);
      reset();
    } catch (error) {
      if (error instanceof ApiError && error.status === 400) {
        setFormError("Current password is incorrect.");
      } else if (error instanceof ApiError && error.status === 429) {
        setFormError("Too many attempts. Wait a moment and try again.");
      } else {
        setFormError("Something went wrong. Try again.");
      }
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-muted-foreground" aria-hidden />
          Password
        </CardTitle>
        <CardDescription>
          Change your password. Every other signed-in session is ended immediately — this one
          stays signed in with the new password.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="current_password">Current password</Label>
            <Input
              id="current_password"
              type="password"
              autoComplete="current-password"
              aria-invalid={!!errors.current_password}
              {...register("current_password")}
            />
            {errors.current_password && (
              <p className="text-sm text-destructive" role="alert">
                {errors.current_password.message}
              </p>
            )}
          </div>
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
              <p className="text-sm text-muted-foreground">At least 12 characters.</p>
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
          {succeeded && <Alert tone="success">Password changed.</Alert>}
          <Button type="submit" className="self-start" isLoading={isSubmitting}>
            {isSubmitting ? "Changing..." : "Change password"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
