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

export const createTargetSchema = z.object({
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
  ]),
  base_url: z
    .string()
    .min(1, "Base URL is required")
    .max(2048)
    .url("Enter a valid URL, e.g. https://staging.example.test"),
});
export type CreateTargetInput = z.infer<typeof createTargetSchema>;

export const createRepositorySchema = z.object({
  name: z.string().min(1, "Name is required").max(200),
  url: z.string().min(1, "Repository URL is required").max(2048),
  branch: z.string().max(200).optional(),
  authorized: z.literal(true, {
    errorMap: () => ({
      message:
        "You must affirm you have the right to have this repository scanned",
    }),
  }),
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
  authorization_confirmed: z.literal(true, {
    errorMap: () => ({
      message: "You must confirm you are authorized to run this assessment",
    }),
  }),
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
});
export type CreateWorkflowInput = z.infer<typeof createWorkflowSchema>;
