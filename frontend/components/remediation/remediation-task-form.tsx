"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { Membership, RemediationRead } from "@/lib/types";
import { remediationUpsertSchema, type RemediationUpsertInput } from "@/lib/validation";

/**
 * Assignee, due date and notes for one finding's remediation task — the
 * same `PUT .../remediation` the CLI's `kervy remediation assign` already
 * calls, exposed in the dashboard. Deliberately cannot touch the finding's
 * own status: that stays the findings endpoint's job, so "who owns this"
 * and "is it still a problem" never drift together.
 */
export function RemediationTaskForm({
  organizationId,
  findingId,
  findingTitle,
  members,
  task,
}: {
  organizationId: string;
  findingId: string;
  findingTitle: string;
  members: Membership[];
  task: RemediationRead | null;
}) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { isSubmitting },
  } = useForm<RemediationUpsertInput>({
    resolver: zodResolver(remediationUpsertSchema),
    defaultValues: {
      summary: task?.summary ?? "",
      assignee_user_id: task?.assignee_user_id ?? "",
      due_date: task?.due_date ?? "",
      notes: task?.notes ?? "",
    },
  });

  async function onSubmit(values: RemediationUpsertInput) {
    setFormError(null);
    try {
      await clientApiFetch<RemediationRead>(
        `/organizations/${organizationId}/findings/${findingId}/remediation`,
        {
          method: "PUT",
          body: JSON.stringify({
            summary: values.summary || undefined,
            assignee_user_id: values.assignee_user_id || null,
            due_date: values.due_date || null,
            notes: values.notes || null,
          }),
        },
      );
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-3">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="remediation-summary">Summary</Label>
        <Input
          id="remediation-summary"
          placeholder={findingTitle}
          {...register("summary")}
        />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="remediation-assignee">Assignee</Label>
        <Select id="remediation-assignee" {...register("assignee_user_id")}>
          <option value="">Unassigned</option>
          {members.map((member) => (
            <option key={member.user_id} value={member.user_id}>
              {member.full_name || member.email}
            </option>
          ))}
        </Select>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="remediation-due-date">Due date</Label>
        <Input id="remediation-due-date" type="date" {...register("due_date")} />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="remediation-notes">Notes</Label>
        <Textarea id="remediation-notes" rows={3} {...register("notes")} />
      </div>
      {formError && <Alert tone="destructive">{formError}</Alert>}
      <Button type="submit" isLoading={isSubmitting} size="sm" className="self-start">
        {isSubmitting ? "Saving..." : "Save"}
      </Button>
    </form>
  );
}
