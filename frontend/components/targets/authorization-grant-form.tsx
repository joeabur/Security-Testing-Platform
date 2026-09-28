"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import { authorizationGrantSchema, type AuthorizationGrantInput } from "@/lib/validation";

function defaultValidUntil(): string {
  const inSevenDays = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  return inSevenDays.toISOString().slice(0, 16);
}

export function AuthorizationGrantForm({
  organizationId,
  targetId,
}: {
  organizationId: string;
  targetId: string;
}) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<AuthorizationGrantInput>({
    resolver: zodResolver(authorizationGrantSchema),
    defaultValues: {
      valid_from: new Date().toISOString().slice(0, 16),
      valid_until: defaultValidUntil(),
    },
  });

  async function onSubmit(values: AuthorizationGrantInput) {
    setFormError(null);
    try {
      await clientApiFetch(`/organizations/${organizationId}/targets/${targetId}/authorization`, {
        method: "POST",
        body: JSON.stringify({
          ...values,
          valid_from: new Date(values.valid_from).toISOString(),
          valid_until: new Date(values.valid_until).toISOString(),
        }),
      });
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="auth-name">Authorized by (name)</Label>
          <Input id="auth-name" placeholder="Jane Doe" {...register("authorized_by_name")} />
          {errors.authorized_by_name && (
            <p className="text-sm text-destructive" role="alert">
              {errors.authorized_by_name.message}
            </p>
          )}
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="auth-role">Their role</Label>
          <Input id="auth-role" placeholder="CISO" {...register("authorized_by_role")} />
          {errors.authorized_by_role && (
            <p className="text-sm text-destructive" role="alert">
              {errors.authorized_by_role.message}
            </p>
          )}
        </div>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="auth-email">Their email</Label>
        <Input id="auth-email" type="email" placeholder="ciso@example.test" {...register("authorized_by_email")} />
        {errors.authorized_by_email && (
          <p className="text-sm text-destructive" role="alert">
            {errors.authorized_by_email.message}
          </p>
        )}
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="auth-reference">Reference</Label>
        <Input
          id="auth-reference"
          placeholder="Ticket, engagement letter, or approval reference"
          {...register("reference")}
        />
        {errors.reference && (
          <p className="text-sm text-destructive" role="alert">
            {errors.reference.message}
          </p>
        )}
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="auth-valid-from">Valid from</Label>
          <Input id="auth-valid-from" type="datetime-local" {...register("valid_from")} />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="auth-valid-until">Valid until</Label>
          <Input id="auth-valid-until" type="datetime-local" {...register("valid_until")} />
          {errors.valid_until && (
            <p className="text-sm text-destructive" role="alert">
              {errors.valid_until.message}
            </p>
          )}
        </div>
      </div>
      {formError && (
        <p className="text-sm text-destructive" role="alert">
          {formError}
        </p>
      )}
      <Button type="submit" disabled={isSubmitting} className="self-start">
        {isSubmitting ? "Granting..." : "Grant authorization"}
      </Button>
    </form>
  );
}
