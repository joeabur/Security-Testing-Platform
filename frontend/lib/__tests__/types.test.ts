import { describe, expect, it } from "vitest";

import { ALLOWED_FINDING_TRANSITIONS } from "@/lib/types";

describe("ALLOWED_FINDING_TRANSITIONS", () => {
  it("mirrors ALLOWED_TRANSITIONS in app/models/finding.py exactly", () => {
    // Any change to the backend map must be made here too — see the
    // comment on ALLOWED_FINDING_TRANSITIONS for why this is duplicated
    // rather than fetched.
    expect(ALLOWED_FINDING_TRANSITIONS).toEqual({
      new: ["confirmed", "false_positive", "accepted_risk", "in_remediation"],
      confirmed: ["in_remediation", "accepted_risk", "false_positive"],
      in_remediation: ["remediated", "accepted_risk", "confirmed"],
      remediated: ["retest_required"],
      retest_required: ["closed", "confirmed"],
      accepted_risk: ["confirmed", "closed"],
      false_positive: ["confirmed", "closed"],
      closed: ["confirmed"],
    });
  });

  it("gives every status somewhere to go — none is a dead end", () => {
    // Even "closed" can move back to "confirmed" if a finding reopens, so
    // FindingStatusForm's own "nothing to transition to" branch is a
    // defensive fallback, not something today's map ever triggers.
    for (const targets of Object.values(ALLOWED_FINDING_TRANSITIONS)) {
      expect(targets.length).toBeGreaterThan(0);
    }
  });
});
