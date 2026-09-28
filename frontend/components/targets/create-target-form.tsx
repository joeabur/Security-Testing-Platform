"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import type { Target } from "@/lib/types";
import { createTargetSchema, type CreateTargetInput } from "@/lib/validation";

const KIND_LABELS: Record<string, string> = {
  llm_app: "LLM application",
  agent: "Agent",
  rag: "RAG pipeline",
  api: "API",
  mcp_server: "MCP server",
  model_endpoint: "Model endpoint",
  web_app: "Web application",
};

export function CreateTargetForm({ organizationId }: { organizationId: string }) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateTargetInput>({
    resolver: zodResolver(createTargetSchema),
    defaultValues: { environment: "staging", kind: "web_app" },
  });

  async function onSubmit(values: CreateTargetInput) {
    setFormError(null);
    try {
      await clientApiFetch<Target>(`/organizations/${organizationId}/targets`, {
        method: "POST",
        body: JSON.stringify(values),
      });
      reset();
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="target-name">Name</Label>
          <Input id="target-name" placeholder="e.g. Staging chatbot" {...register("name")} />
          {errors.name && (
            <p className="text-sm text-destructive" role="alert">
              {errors.name.message}
            </p>
          )}
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="target-environment">Environment</Label>
          <Select id="target-environment" {...register("environment")}>
            <option value="dev">Dev</option>
            <option value="staging">Staging</option>
            <option value="test">Test</option>
            <option value="production">Production</option>
          </Select>
        </div>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="target-kind">Kind</Label>
          <Select id="target-kind" {...register("kind")}>
            {Object.entries(KIND_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </Select>
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="target-base-url">Base URL</Label>
          <Input
            id="target-base-url"
            placeholder="https://staging.example.test"
            {...register("base_url")}
          />
          {errors.base_url && (
            <p className="text-sm text-destructive" role="alert">
              {errors.base_url.message}
            </p>
          )}
        </div>
      </div>
      {formError && (
        <p className="text-sm text-destructive" role="alert">
          {formError}
        </p>
      )}
      <Button type="submit" disabled={isSubmitting} className="self-start">
        {isSubmitting ? "Adding..." : "Add target"}
      </Button>
    </form>
  );
}
