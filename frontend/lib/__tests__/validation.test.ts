import { describe, expect, it } from "vitest";

import {
  createOrganizationSchema,
  findingTransitionSchema,
  loginSchema,
  registerSchema,
  remediationUpsertSchema,
  totpCodeSchema,
  updateWorkflowSchema,
} from "@/lib/validation";

describe("loginSchema", () => {
  it("accepts a valid email and non-empty password", () => {
    const result = loginSchema.safeParse({ email: "user@example.test", password: "anything" });
    expect(result.success).toBe(true);
  });

  it("rejects an invalid email", () => {
    const result = loginSchema.safeParse({ email: "not-an-email", password: "anything" });
    expect(result.success).toBe(false);
  });

  it("rejects an empty password", () => {
    const result = loginSchema.safeParse({ email: "user@example.test", password: "" });
    expect(result.success).toBe(false);
  });
});

describe("registerSchema", () => {
  it("accepts a strong password", () => {
    const result = registerSchema.safeParse({
      email: "user@example.test",
      full_name: "Alice Analyst",
      password: "Correct-Horse-Battery-Staple-9",
    });
    expect(result.success).toBe(true);
  });

  it("rejects a password shorter than 12 characters", () => {
    const result = registerSchema.safeParse({
      email: "user@example.test",
      full_name: "Alice Analyst",
      password: "short",
    });
    expect(result.success).toBe(false);
  });

  it("rejects an empty full name", () => {
    const result = registerSchema.safeParse({
      email: "user@example.test",
      full_name: "",
      password: "Correct-Horse-Battery-Staple-9",
    });
    expect(result.success).toBe(false);
  });
});

describe("totpCodeSchema", () => {
  it("accepts a 6-digit authenticator code", () => {
    const result = totpCodeSchema.safeParse({ code: "123456" });
    expect(result.success).toBe(true);
  });

  it("accepts an 8-character recovery code", () => {
    const result = totpCodeSchema.safeParse({ code: "ABCD2EFG" });
    expect(result.success).toBe(true);
  });

  it("rejects an empty code", () => {
    const result = totpCodeSchema.safeParse({ code: "" });
    expect(result.success).toBe(false);
  });
});

describe("findingTransitionSchema", () => {
  it("accepts a known status with no note", () => {
    const result = findingTransitionSchema.safeParse({ status: "confirmed" });
    expect(result.success).toBe(true);
  });

  it("accepts a known status with a note", () => {
    const result = findingTransitionSchema.safeParse({
      status: "accepted_risk",
      note: "compensating control in place",
    });
    expect(result.success).toBe(true);
  });

  it("rejects an unknown status", () => {
    const result = findingTransitionSchema.safeParse({ status: "not-a-real-status" });
    expect(result.success).toBe(false);
  });
});

describe("createOrganizationSchema", () => {
  it("accepts a non-empty name", () => {
    const result = createOrganizationSchema.safeParse({ name: "Demo Security Lab" });
    expect(result.success).toBe(true);
  });

  it("rejects an empty name", () => {
    const result = createOrganizationSchema.safeParse({ name: "" });
    expect(result.success).toBe(false);
  });
});

describe("remediationUpsertSchema", () => {
  it("accepts every field left blank — nothing is required", () => {
    const result = remediationUpsertSchema.safeParse({
      summary: "",
      assignee_user_id: "",
      due_date: "",
      notes: "",
    });
    expect(result.success).toBe(true);
  });

  it("accepts a fully filled task", () => {
    const result = remediationUpsertSchema.safeParse({
      summary: "Patch the injection sink",
      assignee_user_id: "11111111-1111-1111-1111-111111111111",
      due_date: "2026-12-01",
      notes: "Tracked in JIRA-123",
    });
    expect(result.success).toBe(true);
  });

  it("rejects a summary longer than 300 characters", () => {
    const result = remediationUpsertSchema.safeParse({
      summary: "x".repeat(301),
      assignee_user_id: "",
      due_date: "",
      notes: "",
    });
    expect(result.success).toBe(false);
  });
});

describe("updateWorkflowSchema", () => {
  it("accepts a blank schedule — it clears rather than requires one", () => {
    const result = updateWorkflowSchema.safeParse({
      name: "Staging gate",
      enabled: true,
      schedule_interval_minutes: "",
    });
    expect(result.success).toBe(true);
  });

  it("accepts an interval at the 60-minute floor", () => {
    const result = updateWorkflowSchema.safeParse({
      name: "Staging gate",
      enabled: true,
      schedule_interval_minutes: "60",
    });
    expect(result.success).toBe(true);
  });

  it("rejects an interval below the 60-minute floor", () => {
    const result = updateWorkflowSchema.safeParse({
      name: "Staging gate",
      enabled: true,
      schedule_interval_minutes: "30",
    });
    expect(result.success).toBe(false);
  });

  it("rejects an empty name", () => {
    const result = updateWorkflowSchema.safeParse({
      name: "",
      enabled: true,
      schedule_interval_minutes: "",
    });
    expect(result.success).toBe(false);
  });
});
