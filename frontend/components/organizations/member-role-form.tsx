"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { Membership } from "@/lib/types";
import { updateMemberRoleSchema, type UpdateMemberRoleInput } from "@/lib/validation";

export function MemberRoleForm({
  organizationId,
  member,
  callerIsOwner,
}: {
  organizationId: string;
  member: Membership;
  callerIsOwner: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { isSubmitting },
  } = useForm<UpdateMemberRoleInput>({
    resolver: zodResolver(updateMemberRoleSchema),
    defaultValues: { role: member.role },
  });

  async function onSubmit(values: UpdateMemberRoleInput) {
    setError(null);
    try {
      await clientApiFetch(`/organizations/${organizationId}/members/${member.id}`, {
        method: "PATCH",
        body: JSON.stringify(values),
      });
      router.refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="flex items-center gap-2">
      <Select {...register("role")} className="h-8 w-auto text-xs" aria-label="Role">
        <option value="viewer">Viewer</option>
        <option value="analyst">Analyst</option>
        <option value="security_engineer">Security Engineer</option>
        <option value="admin">Admin</option>
        {(callerIsOwner || member.role === "owner") && <option value="owner">Owner</option>}
      </Select>
      <Button type="submit" size="sm" variant="outline" isLoading={isSubmitting}>
        {isSubmitting ? "Saving..." : "Save"}
      </Button>
      {error && (
        <span className="text-xs text-destructive" role="alert">
          {error}
        </span>
      )}
    </form>
  );
}
