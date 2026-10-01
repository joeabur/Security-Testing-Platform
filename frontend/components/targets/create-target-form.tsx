"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Alert } from "@/components/ui/alert";
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
  container: "Container image",
  cloud_account: "Cloud account",
  virtual_machine: "Virtual machine",
  domain: "Domain",
};

// base_url means something different per kind (backend/app/models/target.py):
// a URL for the adapter-driven kinds above, but an image reference, a cloud
// account ARN/subscription/project id, a VM hostname, or a root domain for
// the pentest-module kinds below. The field's own label and placeholder
// follow whichever kind is selected.
const BASE_URL_FIELD: Record<string, { label: string; placeholder: string }> = {
  container: {
    label: "Image reference",
    placeholder: "123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest",
  },
  cloud_account: {
    label: "Cloud account identifier",
    placeholder: "arn:aws:iam::123456789012:root",
  },
  virtual_machine: {
    label: "VM hostname",
    placeholder: "db1.internal.corp",
  },
  domain: {
    label: "Root domain",
    placeholder: "example.com",
  },
};
const DEFAULT_BASE_URL_FIELD = {
  label: "Base URL",
  placeholder: "https://staging.example.test",
};

export function CreateTargetForm({ organizationId }: { organizationId: string }) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    reset,
    control,
    formState: { errors, isSubmitting },
  } = useForm<CreateTargetInput>({
    resolver: zodResolver(createTargetSchema),
    defaultValues: { environment: "staging", kind: "web_app" },
  });
  const selectedKind = useWatch({ control, name: "kind" });
  const baseUrlField = BASE_URL_FIELD[selectedKind] ?? DEFAULT_BASE_URL_FIELD;

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
          <Label htmlFor="target-base-url">{baseUrlField.label}</Label>
          <Input
            id="target-base-url"
            placeholder={baseUrlField.placeholder}
            {...register("base_url")}
          />
          {errors.base_url && (
            <p className="text-sm text-destructive" role="alert">
              {errors.base_url.message}
            </p>
          )}
        </div>
      </div>
      {formError && <Alert tone="destructive">{formError}</Alert>}
      <Button type="submit" isLoading={isSubmitting} className="self-start">
        {isSubmitting ? "Adding..." : "Add target"}
      </Button>
    </form>
  );
}
