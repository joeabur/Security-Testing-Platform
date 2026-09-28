"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { Repository } from "@/lib/types";
import { createRepositorySchema, type CreateRepositoryInput } from "@/lib/validation";

export function AddRepositoryForm({ organizationId }: { organizationId: string }) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateRepositoryInput>({ resolver: zodResolver(createRepositorySchema) });

  async function onSubmit(values: CreateRepositoryInput) {
    setFormError(null);
    try {
      await clientApiFetch<Repository>(`/organizations/${organizationId}/repositories`, {
        method: "POST",
        body: JSON.stringify({ ...values, branch: values.branch || undefined }),
      });
      reset();
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="repo-name">Name</Label>
          <Input id="repo-name" placeholder="e.g. Payments API" {...register("name")} />
          {errors.name && (
            <p className="text-sm text-destructive" role="alert">
              {errors.name.message}
            </p>
          )}
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="repo-branch">Branch (optional)</Label>
          <Input id="repo-branch" placeholder="main" {...register("branch")} />
        </div>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="repo-url">Repository URL</Label>
        <Input
          id="repo-url"
          placeholder="https://github.com/you/your-repo.git"
          {...register("url")}
        />
        {errors.url && (
          <p className="text-sm text-destructive" role="alert">
            {errors.url.message}
          </p>
        )}
      </div>
      <div className="flex items-start gap-2">
        <Checkbox id="repo-authorized" className="mt-0.5" {...register("authorized")} />
        <Label htmlFor="repo-authorized" className="font-normal">
          I have the right to have this repository scanned (e.g. I own it or have write access).
        </Label>
      </div>
      {errors.authorized && (
        <p className="text-sm text-destructive" role="alert">
          {errors.authorized.message}
        </p>
      )}
      {formError && (
        <p className="text-sm text-destructive" role="alert">
          {formError}
        </p>
      )}
      <Button type="submit" disabled={isSubmitting} className="self-start">
        {isSubmitting ? "Connecting..." : "Connect repository"}
      </Button>
    </form>
  );
}
