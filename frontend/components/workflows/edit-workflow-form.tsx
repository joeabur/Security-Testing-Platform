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
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { Workflow } from "@/lib/types";
import { updateWorkflowSchema, type UpdateWorkflowInput } from "@/lib/validation";

/**
 * Edit (PATCH) and delete (DELETE) for a workflow — both already reachable
 * from `kervy workflow update`/`kervy workflow delete`, missing from the
 * dashboard until now. The gate configuration stays CLI/API-only: a raw
 * JSON editor for it is a separate, larger feature than this convenience
 * gap, not a smaller version of it.
 */
export function EditWorkflowForm({
  organizationId,
  workflow,
}: {
  organizationId: string;
  workflow: Workflow;
}) {
  const router = useRouter();
  const [isEditing, setIsEditing] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { isSubmitting },
  } = useForm<UpdateWorkflowInput>({
    resolver: zodResolver(updateWorkflowSchema),
    defaultValues: {
      name: workflow.name,
      enabled: workflow.enabled,
      schedule_interval_minutes:
        workflow.schedule_interval_minutes != null ? String(workflow.schedule_interval_minutes) : "",
    },
  });

  async function onSubmit(values: UpdateWorkflowInput) {
    setFormError(null);
    try {
      await clientApiFetch<Workflow>(`/organizations/${organizationId}/workflows/${workflow.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          name: values.name,
          enabled: values.enabled,
          schedule_interval_minutes:
            values.schedule_interval_minutes === "" ? null : Number(values.schedule_interval_minutes),
        }),
      });
      setIsEditing(false);
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  async function onDelete() {
    setFormError(null);
    setIsDeleting(true);
    try {
      await clientApiFetch(`/organizations/${organizationId}/workflows/${workflow.id}`, {
        method: "DELETE",
      });
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
      setIsDeleting(false);
    }
  }

  if (!isEditing) {
    return (
      <div className="flex flex-col items-end gap-1.5">
        <div className="flex items-center gap-2">
          <Button type="button" size="sm" variant="outline" onClick={() => setIsEditing(true)}>
            Edit
          </Button>
          <Button
            type="button"
            size="sm"
            variant="destructive"
            onClick={onDelete}
            isLoading={isDeleting}
          >
            {isDeleting ? "Deleting..." : "Delete"}
          </Button>
        </div>
        {formError && (
          <p className="max-w-[16rem] text-right text-xs text-destructive" role="alert">
            {formError}
          </p>
        )}
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex w-full flex-col gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`workflow-name-${workflow.id}`}>Name</Label>
          <Input id={`workflow-name-${workflow.id}`} {...register("name")} />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`workflow-schedule-${workflow.id}`}>Schedule (minutes, blank = off)</Label>
          <Input
            id={`workflow-schedule-${workflow.id}`}
            placeholder="e.g. 1440"
            {...register("schedule_interval_minutes")}
          />
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Checkbox id={`workflow-enabled-${workflow.id}`} {...register("enabled")} />
        <Label htmlFor={`workflow-enabled-${workflow.id}`} className="font-normal">
          Enabled
        </Label>
      </div>
      {formError && <Alert tone="destructive">{formError}</Alert>}
      <div className="flex items-center gap-2">
        <Button type="submit" size="sm" isLoading={isSubmitting}>
          {isSubmitting ? "Saving..." : "Save"}
        </Button>
        <Button type="button" size="sm" variant="outline" onClick={() => setIsEditing(false)}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
