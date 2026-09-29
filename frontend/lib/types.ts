export type Role = "owner" | "admin" | "security_engineer" | "analyst" | "viewer";

export interface User {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
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

export type WorkflowTriggerKind = "repository_change" | "pull_request" | "schedule" | "manual";

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
  minimum_role: string;
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
