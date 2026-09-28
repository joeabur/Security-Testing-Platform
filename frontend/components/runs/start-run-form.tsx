"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { Run } from "@/lib/types";
import { startRunSchema, type StartRunInput } from "@/lib/validation";

export function StartRunForm({ organizationId, targetId }: { organizationId: string; targetId: string }) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<StartRunInput>({
    resolver: zodResolver(startRunSchema),
    defaultValues: { profile: "connectivity", safe_mode: true },
  });

  async function onSubmit(values: StartRunInput) {
    setFormError(null);
    try {
      const run = await clientApiFetch<Run>(`/organizations/${organizationId}/runs`, {
        method: "POST",
        body: JSON.stringify({ ...values, target_id: targetId }),
      });
      router.push(`/organizations/${organizationId}/runs/${run.id}`);
    } catch (error) {
      setFormError(
        error instanceof ApiError
          ? error.message
          : "Something went wrong. Try again.",
      );
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="run-profile">Profile</Label>
        <Select id="run-profile" {...register("profile")}>
          <option value="connectivity">Connectivity (fastest — checks reachability only)</option>
          <option value="quick">Quick</option>
          <option value="full">Full</option>
        </Select>
      </div>
      <div className="flex items-center gap-2">
        <Checkbox id="run-safe-mode" {...register("safe_mode")} />
        <Label htmlFor="run-safe-mode" className="font-normal">
          Safe mode
        </Label>
      </div>
      <div className="flex items-start gap-2">
        <Checkbox id="run-authorized" className="mt-0.5" {...register("authorization_confirmed")} />
        <Label htmlFor="run-authorized" className="font-normal">
          I confirm this assessment is authorized for this target.
        </Label>
      </div>
      {errors.authorization_confirmed && (
        <p className="text-sm text-destructive" role="alert">
          {errors.authorization_confirmed.message}
        </p>
      )}
      {formError && (
        <p className="text-sm text-destructive" role="alert">
          {formError}
        </p>
      )}
      <Button type="submit" disabled={isSubmitting} className="self-start">
        {isSubmitting ? "Starting..." : "Start run"}
      </Button>
    </form>
  );
}
