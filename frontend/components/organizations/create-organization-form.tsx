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
import type { Organization } from "@/lib/types";
import { createOrganizationSchema, type CreateOrganizationInput } from "@/lib/validation";

export function CreateOrganizationForm() {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<CreateOrganizationInput>({ resolver: zodResolver(createOrganizationSchema) });

  async function onSubmit(values: CreateOrganizationInput) {
    setFormError(null);
    try {
      await clientApiFetch<Organization>("/organizations", {
        method: "POST",
        body: JSON.stringify(values),
      });
      router.push("/dashboard");
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="name">Organization name</Label>
        <Input id="name" placeholder="e.g. Demo Security Lab" {...register("name")} />
        {errors.name && (
          <p className="text-sm text-destructive" role="alert">
            {errors.name.message}
          </p>
        )}
      </div>
      {formError && <Alert tone="destructive">{formError}</Alert>}
      <Button type="submit" isLoading={isSubmitting}>
        {isSubmitting ? "Creating..." : "Create organization"}
      </Button>
    </form>
  );
}
