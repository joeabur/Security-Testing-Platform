"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Select } from "@/components/ui/select";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { AgentToolCatalogEntry, Role } from "@/lib/types";
import { agentToolConfigSchema, type AgentToolConfigInput } from "@/lib/validation";

export function AgentToolConfigForm({
  organizationId,
  tool,
}: {
  organizationId: string;
  tool: AgentToolCatalogEntry;
}) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { isSubmitting },
  } = useForm<AgentToolConfigInput>({
    resolver: zodResolver(agentToolConfigSchema),
    defaultValues: {
      enabled: tool.enabled,
      minimum_role_override:
        tool.effective_minimum_role === tool.minimum_role
          ? ""
          : (tool.effective_minimum_role as Role),
    },
  });

  async function onSubmit(values: AgentToolConfigInput) {
    setFormError(null);
    try {
      await clientApiFetch(`/organizations/${organizationId}/agent/tools/${tool.name}/config`, {
        method: "PUT",
        body: JSON.stringify({
          enabled: values.enabled,
          minimum_role_override: values.minimum_role_override || null,
        }),
      });
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="mt-2 flex flex-wrap items-center gap-2">
      <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <Checkbox {...register("enabled")} />
        Enabled
      </label>
      <Select {...register("minimum_role_override")} className="h-8 w-auto text-xs">
        <option value="">Default ({tool.minimum_role})</option>
        <option value="viewer">viewer</option>
        <option value="analyst">analyst</option>
        <option value="security_engineer">security_engineer</option>
        <option value="admin">admin</option>
        <option value="owner">owner</option>
      </Select>
      <Button type="submit" size="sm" variant="outline" isLoading={isSubmitting}>
        {isSubmitting ? "Saving..." : "Save"}
      </Button>
      {formError && <span className="text-xs text-destructive">{formError}</span>}
    </form>
  );
}
