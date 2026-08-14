import { describe, expect, it } from "vitest";
import { cancelDigest, canonicalize, lowercaseHex, registerDigest } from "./adminSign";

// Fixtures generated from Python (geg.core.authz). If the wire config shape or the
// digest scheme changes, regenerate these from register_digest / request_digest.
const CONFIG = {
  electionId: "0x1111111111111111111111111111111111111111111111111111111111111111",
  numCandidates: 3,
  budget: 3,
  mode: "exact",
  variant: "A",
  weighted: true,
  maxWeight: 10,
  duplicatePolicy: "last-wins",
  votingStart: 1000,
  votingEnd: 2000,
  threshold: { t: 2, n: 3 },
  keypers: [
    { signingKey: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", url: "http://k1:8101" },
    { signingKey: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", url: "http://k2:8102" },
    { signingKey: "0xcccccccccccccccccccccccccccccccccccccccc", url: "http://k3:8103" },
  ],
  eligibilityKey:
    "0xe1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1",
  resultPublisherKey: "0xdddddddddddddddddddddddddddddddddddddddd",
  gatewayKeys: ["0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"],
  adminKey: "0xabababababababababababababababababababab",
  protocolVersion: "v1",
  selfSubmitFee: "0", // decimal wei string; part of the signed config
};

const EXPECTED_CANON =
  '{"adminKey":"0xabababababababababababababababababababab","budget":3,"duplicatePolicy":"last-wins","electionId":"0x1111111111111111111111111111111111111111111111111111111111111111","eligibilityKey":"0xe1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1","gatewayKeys":["0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"],"keypers":[{"signingKey":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","url":"http://k1:8101"},{"signingKey":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","url":"http://k2:8102"},{"signingKey":"0xcccccccccccccccccccccccccccccccccccccccc","url":"http://k3:8103"}],"maxWeight":10,"mode":"exact","numCandidates":3,"protocolVersion":"v1","resultPublisherKey":"0xdddddddddddddddddddddddddddddddddddddddd","selfSubmitFee":"0","threshold":{"n":3,"t":2},"variant":"A","votingEnd":2000,"votingStart":1000,"weighted":true}';
const EXPECTED_REGISTER = "0x67ba111b6e42c26cb4af4cc03c4b2ed569c4b6cf512126a31013a67f900406bd";
const EXPECTED_CANCEL = "0x565f20982cb67ac495bf11fd0bba3020cab421e17ce0e8ae697d42f8f06ecce3";
const EID_7 = ("0x" + (7).toString(16).padStart(64, "0")) as `0x${string}`;

describe("admin digests match geg.core.authz (byte-exact)", () => {
  it("canonicalize == Python canonical JSON (electionId included)", () => {
    expect(canonicalize(CONFIG)).toBe(EXPECTED_CANON);
  });
  it("registerDigest == register_digest (binds electionId)", () => {
    expect(registerDigest(CONFIG)).toBe(EXPECTED_REGISTER);
  });
  it("a different asserted electionId yields a different digest (the replay guard)", () => {
    // Signing is per-id: the body that registered election N cannot be replayed to
    // register N+1, because the backend's next id would no longer match what was signed.
    expect(registerDigest({ ...CONFIG, electionId: "0x" + "2".repeat(64) })).not.toBe(EXPECTED_REGISTER);
  });
  it("cancelDigest == request_digest('cancel', eid)", () => {
    expect(cancelDigest(EID_7)).toBe(EXPECTED_CANCEL);
  });
});

describe("lowercaseHex normalizes wallet-checksummed addresses (regression)", () => {
  // wagmi returns EIP-55 checksummed (mixed-case) addresses; the backend re-encodes bytes
  // lowercase before recomputing the digest, so signing the mixed-case form fails
  // verification ("bad admin signature over the config").
  it("a checksummed adminKey yields the SAME digest as lowercase after normalization", () => {
    const checksummed = { ...CONFIG, adminKey: "0xABABABABABABABABABABABABABABABABABABABAB" };
    expect(registerDigest(checksummed)).not.toBe(EXPECTED_REGISTER); // mixed-case would fail
    expect(registerDigest(lowercaseHex(checksummed))).toBe(EXPECTED_REGISTER); // fix restores it
  });

  it("normalizes nested hex (keypers[].signingKey, gatewayKeys) but leaves non-0x strings", () => {
    const out = lowercaseHex({
      variant: "A",
      mode: "exact",
      keypers: [{ signingKey: "0xAAaaBBbb", url: "http://K1:8101" }],
      gatewayKeys: ["0xEEee"],
      adminKey: "0xAbCd",
    });
    expect(out).toEqual({
      variant: "A",            // enum value untouched
      mode: "exact",
      keypers: [{ signingKey: "0xaaaabbbb", url: "http://K1:8101" }], // url case preserved
      gatewayKeys: ["0xeeee"],
      adminKey: "0xabcd",
    });
  });
});
