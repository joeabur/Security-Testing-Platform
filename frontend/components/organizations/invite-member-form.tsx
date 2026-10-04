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
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { Membership, OrganizationInvitation } from "@/lib/types";
import { inviteMemberSchema, type InviteMemberInput } from "@/lib/validation";

export function InviteMemberForm({
  organizationId,
  callerIsOwner,
}: {
  organizationId: string;
  callerIsOwner: boolean;
}) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<InviteMemberInput>({
    resolver: zodResolver(inviteMemberSchema),
    defaultValues: { role: "viewer" },
  });

  async function onSubmit(values: InviteMemberInput) {
    setFormError(null);
    setSuccess(null);
    try {
      // The backend returns one of two different shapes for this call —
      // a Membership (existing account, added immediately) or an
      // OrganizationInvitation (no account yet, a pending invite email was
      // sent) — deliberately different shapes so which one happened is
      // never something this has to guess at from an absent field.
      const result = await clientApiFetch<Membership | OrganizationInvitation>(
        `/organizations/${organizationId}/members`,
        { method: "POST", body: JSON.stringify(values) },
      );
      setSuccess(
        "user_id" in result
          ? `${result.email} was added to the organization.`
          : `An invitation email was sent to ${result.email}.`,
      );
      reset({ email: "", role: "viewer" });
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <div className="grid gap-4 sm:grid-cols-[2fr_1fr]">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="invite-email">Email</Label>
          <Input
            id="invite-email"
            type="email"
            placeholder="teammate@example.com"
            {...register("email")}
          />
          {errors.email && (
            <p className="text-sm text-destructive" role="alert">
              {errors.email.message}
            </p>
          )}
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="invite-role">Role</Label>
          <Select id="invite-role" {...register("role")}>
            <option value="viewer">Viewer</option>
            <option value="analyst">Analyst</option>
            <option value="security_engineer">Security Engineer</option>
            <option value="admin">Admin</option>
            {callerIsOwner && <option value="owner">Owner</option>}
          </Select>
        </div>
      </div>
      {formError && <Alert tone="destructive">{formError}</Alert>}
      {success && <Alert tone="success">{success}</Alert>}
      <Button type="submit" isLoading={isSubmitting} className="self-start">
        {isSubmitting ? "Sending..." : "Invite"}
      </Button>
    </form>
  );
}
