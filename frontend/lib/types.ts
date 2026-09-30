export type Role =
  | "owner"
  | "admin"
  | "security_engineer"
  | "analyst"
  | "viewer";

export interface User {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  totp_enabled: boolean;
}

// --- Two-factor authentication (TOTP) --------------------------------------

/** What `POST /auth/login` returns instead of a session when the account
 * has 2FA enabled — no session yet, just a short-lived ticket
 * `POST /auth/login/2fa` redeems for one. */
export interface TotpChallenge {
  requires_totp: true;
  challenge: string;
}

export interface TotpSetupResponse {
  secret: string;
  provisioning_uri: string;
}

export interface TotpEnableResponse {
  /** Shown to the user exactly once, at enable time — never retrievable
   * again, the same discipline an API key's plaintext token follows. */
  recovery_codes: string[];
}

export interface OAuthProviders {
  google: boolean;
  github: boolean;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  role: Role;
}

export interface Membership {
  id: string;
  user_id: string;
  email: string;
  full_name: string;
  role: Role;
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    request_id: string;
  };
}

export type TargetEnvironment = "staging" | "test" | "dev" | "production";

export type TargetKind =
  | "llm_app"
  | "agent"
  | "rag"
  | "api"
  | "mcp_server"
  | "model_endpoint"
  | "web_app"
  | "code_repo";

export interface Target {
  id: string;
  organization_id: string;
  name: string;
  environment: TargetEnvironment;
  kind: TargetKind;
  base_url: string;
  adapter_kind: string | null;
  has_authorization: boolean;
  has_rules_of_engagement: boolean;
  created_at: string;
}

export interface RulesOfEngagement {
  id: string;
  target_id: string;
  allowed_domains: string[];
  excluded_domains: string[];
  allowed_ip_ranges: string[];
  allowed_paths: string[];
  excluded_paths: string[];
  allowed_methods: string[];
  forbidden_headers: string[];
  budgets: Record<string, number>;
  safe_mode: boolean;
  allow_state_mutation: boolean;
  blackout_windows: unknown[];
}

export interface Authorization {
  id: string;
  target_id: string;
  authorized_by_name: string;
  authorized_by_role: string;
  authorized_by_email: string;
  reference: string;
  valid_from: string;
  valid_until: string;
  accepted_by_user_id: string;
  accepted_at: string;
}

export type RunStatus =
  | "draft"
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "expired";

export const TERMINAL_RUN_STATUSES: readonly RunStatus[] = [
  "completed",
  "failed",
  "cancelled",
  "expired",
];

export interface Run {
  id: string;
  organization_id: string;
  target_id: string;
  status: RunStatus;
  profile: string;
  safe_mode: boolean;
  checks_total: number;
  checks_completed: number;
  requests_used: number;
  requests_blocked: number;
  findings_reported: number;
  halted_reason: string | null;
  error_message: string | null;
  queued_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface RunEvent {
  seq: number;
  kind: string;
  message: string;
  payload: Record<string, unknown> | null;
  occurred_at: string;
}

export interface RepositoryScanSummary {
  run_id: string;
  status: RunStatus;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
}

export interface Repository {
  id: string;
  organization_id: string;
  name: string;
  url: string;
  branch: string | null;
  environment: TargetEnvironment;
  languages: string[];
  build_manifest_paths: string[];
  created_at: string;
  latest_scan: RepositoryScanSummary | null;
}

export type WorkflowTriggerKind =
  | "repository_change"
  | "pull_request"
  | "schedule"
  | "manual";

export interface Workflow {
  id: string;
  organization_id: string;
  target_id: string;
  name: string;
  trigger_kind: string;
  enabled: boolean;
  gate_config: Record<string, unknown> | null;
  created_at: string;
}

export interface WorkflowRun {
  id: string;
  workflow_id: string;
  assessment_run_id: string | null;
  status: string;
  gate_passed: boolean | null;
  gate_reasons: string[];
  started_at: string | null;
  finished_at: string | null;
  detail: string | null;
  created_at: string;
}

// --- Native AI agent (Agent Phase 5) ---------------------------------------
//
// Deliberately no "conversation" or "history" type here: an investigation's
// transcript lives only in this page's React state, for the current
// investigation, never written to localStorage or any store — the frontend
// side of the platform's zero-persistence rule for AI interactions.

export type AgentToolRiskLevel = "read_only" | "standard" | "sensitive";

export interface AgentToolCatalogEntry {
  name: string;
  description: string;
  risk_level: AgentToolRiskLevel;
  // The code default. `effective_minimum_role` is what this organization's
  // own AgentTool override (if any) actually enforces — the two differ
  // exactly when an admin has raised this tool's bar above the code default.
  minimum_role: string;
  effective_minimum_role: string;
  enabled: boolean;
}

export interface AgentToolConfig {
  tool_name: string;
  enabled: boolean;
  minimum_role: string;
  minimum_role_override: string | null;
  effective_minimum_role: string;
}

// --- Exploitation tier (pentest module Phase 12) ---------------------------

export interface ExploitationAuthorization {
  id: string;
  target_id: string;
  authorized_by_name: string;
  authorized_by_role: string;
  authorized_by_email: string;
  reference: string;
  valid_from: string;
  valid_until: string;
  approved_script_names: string[];
  accepted_by_user_id: string;
  accepted_at: string;
}

export type ExploitationFireStatus =
  | "awaiting_approval"
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "rejected";

export interface ExploitationFire {
  id: string;
  target_id: string;
  run_id: string;
  service_host: string;
  service_port: number;
  script_names: string[];
  requested_by_user_id: string;
  requested_at: string;
  approved_by_user_id: string | null;
  approved_at: string | null;
  status: ExploitationFireStatus;
  detail: string | null;
  started_at: string | null;
  finished_at: string | null;
  produced_scan_result_codes: string[];
}

export type InvestigationStatus =
  | "running"
  | "awaiting_approval"
  | "completed"
  | "cancelled"
  | "failed";

export type StepOutcomeStatus =
  | "ok"
  | "tool_not_found"
  | "permission_denied"
  | "approval_required"
  | "execution_error";

export interface StepOutcome {
  tool_name: string;
  status: StepOutcomeStatus;
  result: Record<string, unknown> | null;
  error: string | null;
  duration_ms: number;
}

export interface PendingApproval {
  tool_name: string;
  risk_level: AgentToolRiskLevel;
  description: string;
}

export interface Investigation {
  investigation_id: string;
  status: InvestigationStatus;
  outcomes: StepOutcome[];
  summary: string | null;
  pending_approval: PendingApproval | null;
}

// --- Security operations dashboard (pentest module, Phase 10) --------------

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface PillarCoverageEntry {
  pillar: string;
  tested: boolean;
}

export interface RemediationSummary {
  open: number;
  overdue: number;
}

export interface DashboardRun {
  id: string;
  target_id: string;
  target_name: string;
  status: RunStatus;
  profile: string;
  findings_reported: number;
  created_at: string;
}

export interface DashboardWorkflowRun {
  id: string;
  workflow_id: string;
  workflow_name: string;
  status: string;
  gate_passed: boolean | null;
  created_at: string;
}

export type FindingStatus =
  | "new"
  | "confirmed"
  | "false_positive"
  | "accepted_risk"
  | "in_remediation"
  | "remediated"
  | "retest_required"
  | "closed";

// --- Findings (pentest module Phase 11: the fuller findings view the
// dashboard summary's own top-findings list deliberately deferred — see
// docs/dashboard.md) ---------------------------------------------------

export type Category = "AI_SECURITY" | "API_SECURITY" | "INFRASTRUCTURE" | "DESIGN";
export type Confidence = "LOW" | "MEDIUM" | "HIGH" | "DESIGN_REVIEW";
export type Stability = "deterministic" | "probabilistic" | "single_shot";

/** The §11 finding as the API returns it (`FindingRead`). */
export interface Finding {
  id: string;
  organization_id: string;
  target_id: string | null;
  fingerprint: string;

  title: string;
  category: Category;
  probe_id: string;
  probe_version: string;
  surface: string;

  severity: Severity;
  severity_rationale: string;
  confidence: Confidence;
  stability: Stability;

  risk_model: string;
  risk_score: number;
  risk_inputs: Record<string, unknown>;

  attack_success_rate: Record<string, unknown> | null;
  control_success_rate: Record<string, unknown> | null;
  cvss_v4: Record<string, unknown> | null;
  aivss: Record<string, unknown> | null;

  description: string;
  impact: string;
  remediation: string;
  reproduction: string[];
  mappings: Record<string, unknown>;
  mapping_versions: Record<string, unknown>;

  evidence_ref: string | null;
  retest_result: string | null;
  last_retest_run_id: string | null;

  status: FindingStatus;
  status_note: string | null;
  first_seen: string;
  last_seen: string;
  times_seen: number;

  // Null unless a human has explicitly linked this finding as the same
  // underlying defect as another — never inferred, only recorded.
  duplicate_of_finding_id: string | null;
  duplicate_note: string | null;
}

/** Mirrors `ALLOWED_TRANSITIONS` in `app/models/finding.py` — kept as data
 * here rather than derived, the same "duplicated, with a comment pointing
 * at the source of truth" idiom `ANONYMOUS_CSRF_PATHS` in `lib/config.ts`
 * already uses for a backend constant the frontend must not drift from. */
export const ALLOWED_FINDING_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  new: ["confirmed", "false_positive", "accepted_risk", "in_remediation"],
  confirmed: ["in_remediation", "accepted_risk", "false_positive"],
  in_remediation: ["remediated", "accepted_risk", "confirmed"],
  // A remediation is a claim until a retest checks it, so the only way on
  // from here is through one.
  remediated: ["retest_required"],
  retest_required: ["closed", "confirmed"],
  accepted_risk: ["confirmed", "closed"],
  false_positive: ["confirmed", "closed"],
  closed: ["confirmed"],
};

export interface DashboardFinding {
  id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  status: FindingStatus;
  target_id: string | null;
  target_name: string | null;
  last_seen: string;
}

export interface DashboardSummary {
  targets: number;
  open_findings: number;
  open_findings_by_severity: SeverityCounts;
  runs_last_7_days: number;
  failed_runs_last_7_days: number;
  workflows: number;
  failing_gates_last_7_days: number;
  undelivered_notifications: number;
  remediation: RemediationSummary;
  pending_retests: number;
  pillar_coverage: PillarCoverageEntry[];
  recent_runs: DashboardRun[];
  recent_workflow_runs: DashboardWorkflowRun[];
  top_findings: DashboardFinding[];
}
