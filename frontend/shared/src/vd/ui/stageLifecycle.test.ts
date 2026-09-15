import { describe, expect, it } from "vitest";
import { getStageLifecycle, type StageStatusContext } from "./stageLifecycle";

// Post-voting (phase 4), DKG done — the tally is running. Only the aggregate/decryption
// stages can stall; everything else keeps its normal lifecycle.
const base: StageStatusContext = {
  isDKGFinalized: true,
  phase: 4,
  isResultFinalized: false,
  thresholdT: 1,
  aggregate: null,
  shares: null,
};

describe("getStageLifecycle — stalled overlay", () => {
  it("aggregate stage (3) reads stalled when no aggregate has formed", () => {
    expect(getStageLifecycle(3, { ...base, tallyStalled: true })).toBe("stalled");
    // without the flag it's just the active stage
    expect(getStageLifecycle(3, base)).toBe("in_progress");
  });

  it("decryption stage (4) reads stalled once the aggregate is sealed but shares are short", () => {
    const ctx = { ...base, aggregate: { aggregates: [] } as any, tallyStalled: true };
    expect(getStageLifecycle(4, ctx)).toBe("stalled");
    expect(getStageLifecycle(4, { ...ctx, tallyStalled: false })).toBe("in_progress");
  });

  it("only the active (stuck) stage stalls — completed and not-yet-started stages are unaffected", () => {
    const ctx = { ...base, tallyStalled: true };
    expect(getStageLifecycle(1, ctx)).toBe("done"); // DKG finalized
    expect(getStageLifecycle(2, ctx)).toBe("done"); // voting closed
    expect(getStageLifecycle(4, ctx)).toBe("pending"); // aggregate not formed yet → decryption not active
  });

  it("a published result wins — the stage is done, not stalled, even if the flag lingers", () => {
    const ctx: StageStatusContext = {
      ...base,
      aggregate: { aggregates: [] } as any,
      shares: [{ keyperIndex: 0 } as any],
      isResultFinalized: true,
      tallyStalled: true,
    };
    expect(getStageLifecycle(5, ctx)).toBe("done");
  });
});
