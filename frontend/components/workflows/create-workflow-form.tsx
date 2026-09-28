"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { Target, Workflow } from "@/lib/types";
import { createWorkflowSchema, type CreateWorkflowInput } from "@/lib/validation";

export function CreateWorkflowForm({
  organizationId,
  targets,
}: {
  organizationId: string;
  targets: Target[];
}) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateWorkflowInput>({
    resolver: zodResolver(createWorkflowSchema),
    defaultValues: { trigger_kind: "manual", enabled: true },
  });

  async function onSubmit(values: CreateWorkflowInput) {
    setFormError(null);
    try {
      await clientApiFetch<Workflow>(`/organizations/${organizationId}/workflows`, {
        method: "POST",
        body: JSON.stringify(values),
      });
      reset();
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  if (targets.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        Add a target first — a workflow is defined against one.
      </p>
    );
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="workflow-name">Name</Label>
          <Input id="workflow-name" placeholder="e.g. Staging gate" {...register("name")} />
          {errors.name && (
            <p className="text-sm text-destructive" role="alert">
              {errors.name.message}
            </p>
          )}
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="workflow-target">Target</Label>
          <Select id="workflow-target" {...register("target_id")}>
            {targets.map((target) => (
              <option key={target.id} value={target.id}>
                {target.name}
              </option>
            ))}
          </Select>
        </div>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="workflow-trigger">Trigger</Label>
        <Select id="workflow-trigger" {...register("trigger_kind")}>
          <option value="manual">Manual</option>
          <option value="repository_change">Repository change</option>
          <option value="pull_request">Pull request</option>
          <option value="schedule">Schedule</option>
        </Select>
      </div>
      <div className="flex items-center gap-2">
        <Checkbox id="workflow-enabled" {...register("enabled")} />
        <Label htmlFor="workflow-enabled" className="font-normal">
          Enabled
        </Label>
      </div>
      {formError && (
        <p className="text-sm text-destructive" role="alert">
          {formError}
        </p>
      )}
      <Button type="submit" disabled={isSubmitting} className="self-start">
        {isSubmitting ? "Creating..." : "Create workflow"}
      </Button>
    </form>
  );
}
