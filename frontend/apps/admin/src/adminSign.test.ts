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
  threshold: { t: 1, n: 3 },
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
  '{"adminKey":"0xabababababababababababababababababababab","budget":3,"duplicatePolicy":"last-wins","electionId":"0x0000000000000000000000000000000000000000000000000000000000000000","eligibilityKey":"0xe1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1","gatewayKeys":["0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"],"keypers":[{"signingKey":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","url":"http://k1:8101"},{"signingKey":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","url":"http://k2:8102"},{"signingKey":"0xcccccccccccccccccccccccccccccccccccccccc","url":"http://k3:8103"}],"maxWeight":10,"mode":"exact","numCandidates":3,"protocolVersion":"v1","resultPublisherKey":"0xdddddddddddddddddddddddddddddddddddddddd","selfSubmitFee":"0","threshold":{"n":3,"t":1},"variant":"A","votingEnd":2000,"votingStart":1000,"weighted":true}';
const EXPECTED_REGISTER = "0x61d01b9779cd7681537c0a6ccc21cd82b7ea51c04c2cbaae66ab349b5e563482";
const EXPECTED_CANCEL = "0x2fe6f4c5c76a0413ccc9bd1b4b11bfc872c0c6c747f4477ff0c7033d69410669";
const EID_7 = ("0x" + (7).toString(16).padStart(64, "0")) as `0x${string}`;

describe("admin digests match geg.core.authz (byte-exact)", () => {
  it("canonicalize == Python canonical JSON (electionId zeroed)", () => {
    expect(canonicalize({ ...CONFIG, electionId: "0x" + "0".repeat(64) })).toBe(EXPECTED_CANON);
  });
  it("registerDigest == register_digest (zeroes electionId itself)", () => {
    expect(registerDigest(CONFIG)).toBe(EXPECTED_REGISTER);
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
