"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Alert } from "@/components/ui/alert";
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
    watch,
    formState: { errors, isSubmitting },
  } = useForm<CreateWorkflowInput>({
    resolver: zodResolver(createWorkflowSchema),
    defaultValues: { trigger_kind: "manual", enabled: true, schedule_interval_minutes: "" },
  });
  const triggerKind = watch("trigger_kind");

  async function onSubmit(values: CreateWorkflowInput) {
    setFormError(null);
    try {
      const { schedule_interval_minutes, ...rest } = values;
      await clientApiFetch<Workflow>(`/organizations/${organizationId}/workflows`, {
        method: "POST",
        body: JSON.stringify({
          ...rest,
          schedule_interval_minutes:
            schedule_interval_minutes === "" ? null : Number(schedule_interval_minutes),
        }),
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
      {triggerKind === "schedule" && (
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="workflow-schedule-interval">Run every (minutes)</Label>
          <Input
            id="workflow-schedule-interval"
            type="number"
            min={60}
            placeholder="60"
            {...register("schedule_interval_minutes")}
          />
          <p className="text-xs text-muted-foreground">
            Minimum 60 minutes. Left blank, this workflow is created but never runs on its own —
            it can be scheduled later from the workflow&apos;s edit form.
          </p>
          {errors.schedule_interval_minutes && (
            <p className="text-sm text-destructive" role="alert">
              {errors.schedule_interval_minutes.message}
            </p>
          )}
        </div>
      )}
      <div className="flex items-center gap-2">
        <Checkbox id="workflow-enabled" {...register("enabled")} />
        <Label htmlFor="workflow-enabled" className="font-normal">
          Enabled
        </Label>
      </div>
      {formError && <Alert tone="destructive">{formError}</Alert>}
      <Button type="submit" isLoading={isSubmitting} className="self-start">
        {isSubmitting ? "Creating..." : "Create workflow"}
      </Button>
    </form>
  );
}
