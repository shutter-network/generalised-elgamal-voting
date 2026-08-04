import { describe, expect, it } from "vitest";
import { deriveState, isVotingOpen } from "./state";

const C = { votingStart: 1000, votingEnd: 2000 };
const facts = (o: Partial<{ cancelled: boolean; keyFinalized: boolean; resultPublished: boolean }> = {}) => ({
  cancelled: false,
  keyFinalized: false,
  resultPublished: false,
  ...o,
});

describe("deriveState (mirror of geg.core.state.derive_state)", () => {
  it("cancelled wins over everything", () => {
    expect(deriveState(C, facts({ cancelled: true, resultPublished: true }), 500)).toBe("Cancelled");
  });
  it("published result -> Complete", () => {
    expect(deriveState(C, facts({ keyFinalized: true, resultPublished: true }), 2500)).toBe("Complete");
  });
  it("voting opened without a key -> DKGFailed", () => {
    expect(deriveState(C, facts(), 1000)).toBe("DKGFailed");
  });
  it("no key before voting_start -> Registered", () => {
    expect(deriveState(C, facts(), 500)).toBe("Registered");
  });
  it("key finalized before voting_start -> KeyReady", () => {
    expect(deriveState(C, facts({ keyFinalized: true }), 500)).toBe("KeyReady");
  });
  it("inside window with key -> Voting", () => {
    expect(deriveState(C, facts({ keyFinalized: true }), 1500)).toBe("Voting");
  });
  it("after voting_end, key, no result -> Tallying", () => {
    expect(deriveState(C, facts({ keyFinalized: true }), 2500)).toBe("Tallying");
  });
});

describe("isVotingOpen (half-open [start,end))", () => {
  it("start inclusive, end exclusive", () => {
    expect(isVotingOpen(C, 999)).toBe(false);
    expect(isVotingOpen(C, 1000)).toBe(true);
    expect(isVotingOpen(C, 1999)).toBe(true);
    expect(isVotingOpen(C, 2000)).toBe(false);
  });
});
