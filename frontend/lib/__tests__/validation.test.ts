import { describe, expect, it } from "vitest";

import {
  createOrganizationSchema,
  findingTransitionSchema,
  loginSchema,
  registerSchema,
  totpCodeSchema,
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
