import { describe, expect, it } from "vitest";

import { toLocalDatetimeInputValue } from "@/lib/dates";

describe("toLocalDatetimeInputValue", () => {
  it("formats using local time components, not UTC", () => {
    // A date constructed from explicit local components — never
    // `toISOString()`, which is UTC and would shift the clock time by the
    // runner's own offset whenever it isn't exactly zero.
    const date = new Date(2026, 0, 5, 9, 3); // Jan 5 2026, 09:03 local
    expect(toLocalDatetimeInputValue(date)).toBe("2026-01-05T09:03");
  });

  it("zero-pads single-digit month, day, hour and minute", () => {
    const date = new Date(2026, 8, 2, 1, 7); // Sep 2 2026, 01:07 local
    expect(toLocalDatetimeInputValue(date)).toBe("2026-09-02T01:07");
  });
});
