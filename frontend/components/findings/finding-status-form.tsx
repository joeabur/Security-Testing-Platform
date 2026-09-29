"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import { ALLOWED_FINDING_TRANSITIONS, type Finding, type FindingStatus } from "@/lib/types";
import { findingTransitionSchema, type FindingTransitionInput } from "@/lib/validation";

function statusLabel(status: FindingStatus): string {
  return status.replace(/_/g, " ");
}

export function FindingStatusForm({
  organizationId,
  finding,
}: {
  organizationId: string;
  finding: Finding;
}) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const allowed = ALLOWED_FINDING_TRANSITIONS[finding.status];
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<FindingTransitionInput>({
    resolver: zodResolver(findingTransitionSchema),
    defaultValues: { status: allowed[0] },
  });

  if (allowed.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        This finding&apos;s status ({statusLabel(finding.status)}) is terminal — nothing to
        transition to.
      </p>
    );
  }

  async function onSubmit(values: FindingTransitionInput) {
    setFormError(null);
    try {
      await clientApiFetch<Finding>(
        `/organizations/${organizationId}/findings/${finding.id}/status`,
        { method: "POST", body: JSON.stringify(values) },
      );
      router.refresh();
    } catch (error) {
      setFormError(
        error instanceof ApiError
          ? error.message
          : "Something went wrong. Try again.",
      );
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-3">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="finding-status">Move to</Label>
        <Select id="finding-status" {...register("status")}>
          {allowed.map((status) => (
            <option key={status} value={status}>
              {statusLabel(status)}
            </option>
          ))}
        </Select>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="finding-note">Note (optional)</Label>
        <Textarea
          id="finding-note"
          rows={3}
          placeholder="Why is this changing?"
          aria-invalid={!!errors.note}
          {...register("note")}
        />
        {errors.note && (
          <p className="text-sm text-destructive" role="alert">
            {errors.note.message}
          </p>
        )}
      </div>
      {formError && <Alert tone="destructive">{formError}</Alert>}
      <Button type="submit" isLoading={isSubmitting} size="sm" className="self-start">
        {isSubmitting ? "Updating..." : "Update status"}
      </Button>
    </form>
  );
}
