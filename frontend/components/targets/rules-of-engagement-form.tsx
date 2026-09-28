"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { clientApiFetch } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import { rulesOfEngagementSchema, splitCsv, type RulesOfEngagementInput } from "@/lib/validation";

// Fixed, conservative defaults for the fields this form doesn't expose —
// the same values docs/installation.md's quickstart uses. An operator who
// needs different budgets or a blackout window uses the API directly
// (docs/authorization-and-scope.md); this form covers the fields every
// first run actually needs to set.
const FIXED_DEFAULTS = {
  excluded_domains: [] as string[],
  excluded_paths: [] as string[],
  forbidden_headers: [] as string[],
  allow_state_mutation: false,
  blackout_windows: [] as unknown[],
  budgets: {
    max_requests: 600,
    max_concurrency: 4,
    requests_per_second: 200.0,
    max_tokens_sent: 200_000,
    max_tokens_received: 200_000,
    max_estimated_cost_usd: 5.0,
    max_wall_clock_minutes: 10,
  },
};

export function RulesOfEngagementForm({
  organizationId,
  targetId,
}: {
  organizationId: string;
  targetId: string;
}) {
  const router = useRouter();
  const [formError, setFormError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    formState: { isSubmitting },
  } = useForm<RulesOfEngagementInput>({
    resolver: zodResolver(rulesOfEngagementSchema),
    defaultValues: { safe_mode: true, allowed_methods: "GET, POST" },
  });

  async function onSubmit(values: RulesOfEngagementInput) {
    setFormError(null);
    try {
      await clientApiFetch(
        `/organizations/${organizationId}/targets/${targetId}/rules-of-engagement`,
        {
          method: "PUT",
          body: JSON.stringify({
            ...FIXED_DEFAULTS,
            allowed_domains: splitCsv(values.allowed_domains),
            allowed_ip_ranges: splitCsv(values.allowed_ip_ranges),
            allowed_paths: splitCsv(values.allowed_paths),
            allowed_methods: splitCsv(values.allowed_methods),
            safe_mode: values.safe_mode,
          }),
        },
      );
      router.refresh();
    } catch (error) {
      setFormError(error instanceof ApiError ? error.message : "Something went wrong. Try again.");
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-4">
      <p className="text-xs text-muted-foreground">
        Comma-separated. Loopback targets need <code>127.0.0.1</code> explicitly listed under
        allowed IP ranges — it is blocked by default.
      </p>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="roe-domains">Allowed domains</Label>
        <Input id="roe-domains" placeholder="staging.example.test" {...register("allowed_domains")} />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="roe-ips">Allowed IP ranges</Label>
        <Input id="roe-ips" placeholder="127.0.0.0/8" {...register("allowed_ip_ranges")} />
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="roe-paths">Allowed paths</Label>
          <Input id="roe-paths" placeholder="/, /api/**" {...register("allowed_paths")} />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="roe-methods">Allowed methods</Label>
          <Input id="roe-methods" placeholder="GET, POST" {...register("allowed_methods")} />
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Checkbox id="roe-safe-mode" {...register("safe_mode")} />
        <Label htmlFor="roe-safe-mode" className="font-normal">
          Safe mode (skip payloads that could mutate state)
        </Label>
      </div>
      {formError && (
        <p className="text-sm text-destructive" role="alert">
          {formError}
        </p>
      )}
      <Button type="submit" disabled={isSubmitting} className="self-start">
        {isSubmitting ? "Saving..." : "Save Rules of Engagement"}
      </Button>
    </form>
  );
}
