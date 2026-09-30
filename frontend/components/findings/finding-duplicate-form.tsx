"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { Finding } from "@/lib/types";
import { findingDuplicateLinkSchema, type FindingDuplicateLinkInput } from "@/lib/validation";

export function FindingDuplicateForm({
  organizationId,
  finding,
}: {
  organizationId: string;
  finding: Finding;
}) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const [isUnlinking, setIsUnlinking] = useState(false);
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<FindingDuplicateLinkInput>({
    resolver: zodResolver(findingDuplicateLinkSchema),
  });

  async function onUnlink() {
    setFormError(null);
    setIsUnlinking(true);
    try {
      await clientApiFetch<Finding>(
        `/organizations/${organizationId}/findings/${finding.id}/duplicate`,
        { method: "DELETE" },
      );
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    } finally {
      setIsUnlinking(false);
    }
  }

  if (finding.duplicate_of_finding_id) {
    return (
      <div className="flex flex-col gap-3">
        <p className="text-sm text-foreground">
          Marked as a duplicate of finding{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">
            {finding.duplicate_of_finding_id}
          </code>
          .
        </p>
        {finding.duplicate_note && (
          <p className="whitespace-pre-wrap text-sm text-muted-foreground">
            {finding.duplicate_note}
          </p>
        )}
        {formError && <Alert tone="destructive">{formError}</Alert>}
        <Button
          type="button"
          variant="outline"
          size="sm"
          isLoading={isUnlinking}
          onClick={onUnlink}
          className="self-start"
        >
          {isUnlinking ? "Unlinking..." : "Unlink"}
        </Button>
      </div>
    );
  }

  async function onSubmit(values: FindingDuplicateLinkInput) {
    setFormError(null);
    try {
      await clientApiFetch<Finding>(
        `/organizations/${organizationId}/findings/${finding.id}/duplicate`,
        { method: "POST", body: JSON.stringify(values) },
      );
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-3">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="duplicate-of">Duplicate of finding ID</Label>
        <Input
          id="duplicate-of"
          placeholder="Paste the other finding's ID"
          {...register("duplicate_of_finding_id")}
        />
        {errors.duplicate_of_finding_id && (
          <p className="text-sm text-destructive" role="alert">
            {errors.duplicate_of_finding_id.message}
          </p>
        )}
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="duplicate-note">Note (optional)</Label>
        <Textarea
          id="duplicate-note"
          rows={2}
          placeholder="Why are these the same underlying defect?"
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
        {isSubmitting ? "Linking..." : "Mark as duplicate"}
      </Button>
    </form>
  );
}
