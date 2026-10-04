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
  const [notice, setNotice] = useState<{ tone: "success" | "warning"; message: string } | null>(
    null,
  );
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
    setNotice(null);
    try {
      // The backend returns one of two different shapes for this call —
      // a Membership (existing account, added immediately) or an
      // OrganizationInvitation (no account yet, a pending invite created) —
      // deliberately different shapes so which one happened is never
      // something this has to guess at from an absent field. The
      // invitation shape additionally carries `email_sent`, since creating
      // the row and actually delivering the email are two different
      // things — whether no relay is configured at all, or a configured
      // one failed to deliver, the row is still created (so the invite can
      // be revoked and re-sent later), but nothing went out, and the UI
      // has no business implying otherwise.
      const result = await clientApiFetch<Membership | OrganizationInvitation>(
        `/organizations/${organizationId}/members`,
        { method: "POST", body: JSON.stringify(values) },
      );
      if ("user_id" in result) {
        setNotice({ tone: "success", message: `${result.email} was added to the organization.` });
      } else if (result.email_sent) {
        setNotice({
          tone: "success",
          message: `An invitation email was sent to ${result.email}.`,
        });
      } else {
        // `email_sent` is false both when no relay is configured at all
        // and when a configured one failed to deliver (wrong credentials,
        // refused STARTTLS, connection refused) — the response doesn't
        // distinguish which, so this says only what's true in both cases
        // rather than guessing a specific cause.
        setNotice({
          tone: "warning",
          message:
            `An invitation was created for ${result.email}, but the email could not be ` +
            "delivered. Ask an administrator to check this server's outbound mail setup " +
            "(KERVY_PLATFORM_SMTP_HOST and related settings), then revoke and re-invite " +
            "once it's working.",
        });
      }
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
      {notice && <Alert tone={notice.tone}>{notice.message}</Alert>}
      <Button type="submit" isLoading={isSubmitting} className="self-start">
        {isSubmitting ? "Sending..." : "Invite"}
      </Button>
    </form>
  );
}
