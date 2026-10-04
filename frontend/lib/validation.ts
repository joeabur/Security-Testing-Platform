import { z } from "zod";

export const loginSchema = z.object({
  email: z
    .string()
    .min(1, "Email is required")
    .email("Enter a valid email address"),
  password: z.string().min(1, "Password is required"),
});
export type LoginInput = z.infer<typeof loginSchema>;

export const registerSchema = z.object({
  email: z
    .string()
    .min(1, "Email is required")
    .email("Enter a valid email address"),
  full_name: z.string().min(1, "Name is required").max(200),
  password: z
    .string()
    .min(12, "Password must be at least 12 characters")
    .max(200, "Password is too long"),
});
export type RegisterInput = z.infer<typeof registerSchema>;

export const forgotPasswordSchema = z.object({
  email: z
    .string()
    .min(1, "Email is required")
    .email("Enter a valid email address"),
});
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;

export const resetPasswordSchema = z
  .object({
    new_password: z
      .string()
      .min(12, "Password must be at least 12 characters")
      .max(200, "Password is too long"),
    confirm_password: z.string().min(1, "Confirm your new password"),
  })
  .refine((value) => value.new_password === value.confirm_password, {
    message: "Passwords do not match",
    path: ["confirm_password"],
  });
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;

// A 6-digit TOTP code or an 8-character recovery code (the digest-only
// TotpRecoveryCode shape backend/app/models/totp_recovery_code.py mints) —
// `_verify_totp_or_recovery_code` accepts either, so this input does too.
export const totpCodeSchema = z.object({
  code: z
    .string()
    .min(1, "Enter the 6-digit code from your authenticator app")
    .max(32, "That code is too long"),
});
export type TotpCodeInput = z.infer<typeof totpCodeSchema>;

export const createOrganizationSchema = z.object({
  name: z.string().min(1, "Organization name is required").max(200),
});
export type CreateOrganizationInput = z.infer<typeof createOrganizationSchema>;

// The pentest-module kinds (backend/app/models/target.py's own comment)
// repurpose base_url as an image reference, a cloud account ARN/
// subscription/project id, or a VM hostname/domain rather than a URL, so
// only the kinds with a real network/adapter surface require URL-shaped
// input.
const URL_BASED_TARGET_KINDS = new Set([
  "llm_app",
  "agent",
  "rag",
  "api",
  "mcp_server",
  "model_endpoint",
  "web_app",
]);
const targetUrlSchema = z.string().url();

export const createTargetSchema = z
  .object({
    name: z.string().min(1, "Name is required").max(200),
    environment: z.enum(["staging", "test", "dev", "production"]),
    kind: z.enum([
      "llm_app",
      "agent",
      "rag",
      "api",
      "mcp_server",
      "model_endpoint",
      "web_app",
      "container",
      "cloud_account",
      "virtual_machine",
      "domain",
    ]),
    base_url: z.string().min(1, "This field is required").max(2048),
  })
  .superRefine((value, ctx) => {
    if (
      URL_BASED_TARGET_KINDS.has(value.kind) &&
      !targetUrlSchema.safeParse(value.base_url).success
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Enter a valid URL, e.g. https://staging.example.test",
        path: ["base_url"],
      });
    }
  });
export type CreateTargetInput = z.infer<typeof createTargetSchema>;

export const createRepositorySchema = z.object({
  name: z.string().min(1, "Name is required").max(200),
  url: z.string().min(1, "Repository URL is required").max(2048),
  branch: z.string().max(200).optional(),
  authorized: z.literal(
    true,
    "You must affirm you have the right to have this repository scanned",
  ),
});
export type CreateRepositoryInput = z.infer<typeof createRepositorySchema>;

// Comma-separated lists, e.g. "example.test, api.example.test" — the RoE
// form's essential fields; budgets use fixed sane defaults (see
// components/targets/rules-of-engagement-form.tsx) rather than a dozen more
// numeric inputs nobody will tune on their first run. Kept as plain strings
// here (not split into arrays) so the field's input and output types match —
// splitting happens in the form's submit handler instead.
export const rulesOfEngagementSchema = z.object({
  allowed_domains: z.string().optional(),
  allowed_ip_ranges: z.string().optional(),
  allowed_paths: z.string().optional(),
  allowed_methods: z.string().optional(),
  safe_mode: z.boolean(),
});
export type RulesOfEngagementInput = z.infer<typeof rulesOfEngagementSchema>;

export function splitCsv(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export const authorizationGrantSchema = z
  .object({
    authorized_by_name: z.string().min(1, "Required").max(200),
    authorized_by_role: z.string().min(1, "Required").max(100),
    authorized_by_email: z
      .string()
      .min(1, "Required")
      .email("Enter a valid email address"),
    reference: z.string().min(1, "Required").max(500),
    valid_from: z.string().min(1, "Required"),
    valid_until: z.string().min(1, "Required"),
  })
  .refine((value) => new Date(value.valid_until) > new Date(value.valid_from), {
    message: "Valid until must be after valid from",
    path: ["valid_until"],
  });
export type AuthorizationGrantInput = z.infer<typeof authorizationGrantSchema>;

export const startRunSchema = z.object({
  profile: z.enum(["connectivity", "quick", "full"]),
  safe_mode: z.boolean(),
  authorization_confirmed: z.literal(
    true,
    "You must confirm you are authorized to run this assessment",
  ),
});
export type StartRunInput = z.infer<typeof startRunSchema>;

export const findingTransitionSchema = z.object({
  status: z.enum([
    "new",
    "confirmed",
    "false_positive",
    "accepted_risk",
    "in_remediation",
    "remediated",
    "retest_required",
    "closed",
  ]),
  note: z.string().max(2000).optional(),
});
export type FindingTransitionInput = z.infer<typeof findingTransitionSchema>;

export const findingDuplicateLinkSchema = z.object({
  duplicate_of_finding_id: z.string().min(1, "Choose the finding this duplicates"),
  note: z.string().max(1000).optional(),
});
export type FindingDuplicateLinkInput = z.infer<typeof findingDuplicateLinkSchema>;

export const agentToolConfigSchema = z.object({
  enabled: z.boolean(),
  // "" means "no override" (clears back to the code default) — kept as a
  // plain string here so a <Select> can use it directly; the submit
  // handler maps "" to null before sending it to the API.
  minimum_role_override: z.enum([
    "",
    "owner",
    "admin",
    "security_engineer",
    "analyst",
    "viewer",
  ]),
});
export type AgentToolConfigInput = z.infer<typeof agentToolConfigSchema>;

export const exploitationAuthorizationGrantSchema = z
  .object({
    authorized_by_name: z.string().min(1, "Required").max(200),
    authorized_by_role: z.string().min(1, "Required").max(100),
    authorized_by_email: z
      .string()
      .min(1, "Required")
      .email("Enter a valid email address"),
    reference: z.string().min(1, "Required").max(500),
    valid_from: z.string().min(1, "Required"),
    valid_until: z.string().min(1, "Required"),
    // Comma-separated NSE script names, e.g. "http-vuln-cve2021-41773" —
    // split in the form's submit handler via splitCsv, same idiom the RoE
    // form already uses for its own comma-separated fields.
    approved_script_names: z.string().min(1, "At least one script name is required"),
  })
  .refine((value) => new Date(value.valid_until) > new Date(value.valid_from), {
    message: "Valid until must be after valid from",
    path: ["valid_until"],
  });
export type ExploitationAuthorizationGrantInput = z.infer<
  typeof exploitationAuthorizationGrantSchema
>;

export const exploitationFireCreateSchema = z.object({
  service_host: z.string().min(1, "Required").max(255),
  service_port: z.coerce.number().int().min(1).max(65535),
  script_names: z.string().min(1, "At least one script name is required"),
  authorization_confirmed: z.literal(
    true,
    "You must confirm you are authorized to fire this exploit",
  ),
});
export type ExploitationFireCreateInput = z.infer<typeof exploitationFireCreateSchema>;
// react-hook-form's register() sees the pre-coerce shape (service_port as
// unknown/string from the <input>), while onSubmit receives the post-coerce
// ExploitationFireCreateInput above — z.coerce.number() makes those differ.
export type ExploitationFireCreateFormInput = z.input<typeof exploitationFireCreateSchema>;

export const exploitationFireRejectSchema = z.object({
  reason: z.string().min(1, "A reason is required").max(1000),
});
export type ExploitationFireRejectInput = z.infer<typeof exploitationFireRejectSchema>;

export const createWorkflowSchema = z.object({
  name: z.string().min(1, "Name is required").max(120),
  target_id: z.string().min(1, "Choose a target"),
  trigger_kind: z.enum([
    "repository_change",
    "pull_request",
    "schedule",
    "manual",
  ]),
  enabled: z.boolean(),
  // Only meaningful when trigger_kind is "schedule" — left "" (the
  // default), this workflow is created but never picked up by the
  // scheduler, matching app/schemas/workflow.py's own "silence is the
  // inert state" default. Same floor as updateWorkflowSchema's own field.
  schedule_interval_minutes: z
    .string()
    .refine((value) => value === "" || Number(value) >= 60, "Minimum interval is 60 minutes"),
});
export type CreateWorkflowInput = z.infer<typeof createWorkflowSchema>;

export const updateWorkflowSchema = z.object({
  name: z.string().min(1, "Name is required").max(120),
  enabled: z.boolean(),
  // "" clears the schedule (sent to the API as null); otherwise it must
  // meet MIN_SCHEDULE_INTERVAL_MINUTES, matching app/schemas/workflow.py's
  // own floor against unattended, repeated scanning of a live target.
  schedule_interval_minutes: z
    .string()
    .refine((value) => value === "" || Number(value) >= 60, "Minimum interval is 60 minutes"),
});
export type UpdateWorkflowInput = z.infer<typeof updateWorkflowSchema>;

export const remediationUpsertSchema = z.object({
  summary: z.string().max(300).optional().or(z.literal("")),
  // "" means unassigned, the same convention agentToolConfigSchema's
  // minimum_role_override uses for "no override" — the submit handler maps
  // it to null before sending it to the API.
  assignee_user_id: z.string(),
  due_date: z.string().optional().or(z.literal("")),
  notes: z.string().max(4000).optional().or(z.literal("")),
});
export type RemediationUpsertInput = z.infer<typeof remediationUpsertSchema>;
