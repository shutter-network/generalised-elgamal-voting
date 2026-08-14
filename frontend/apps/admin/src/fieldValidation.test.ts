import { describe, expect, it } from "vitest";
import {
  ADDRESS_BYTES,
  ELIGIBILITY_KEY_BYTES,
  optionalAddress,
  requireAddress,
  requireEligibilityKey,
  requireHexBytes,
  sponsorAddress,
} from "./fieldValidation";

const ADDR = "0x" + "ab".repeat(ADDRESS_BYTES); // 20 bytes
const G1 = "0x" + "e1".repeat(ELIGIBILITY_KEY_BYTES); // 48 bytes
const ZERO = "0x" + "0".repeat(2 * ADDRESS_BYTES);

describe("requireHexBytes", () => {
  it("accepts an exact-length value and lowercases it", () => {
    // Lowercasing is load-bearing: the backend re-encodes to lowercase before recomputing
    // the register digest, so a checksummed address would be signed in a different form.
    expect(requireHexBytes("0x" + "AB".repeat(20), 20, "F")).toBe("0x" + "ab".repeat(20));
  });

  it("trims surrounding whitespace (pasted values often carry it)", () => {
    expect(requireHexBytes(`  ${ADDR}\n`, 20, "F")).toBe(ADDR);
  });

  it.each([
    ["empty", "", /required/],
    ["whitespace only", "   ", /required/],
    ["missing 0x", "ab".repeat(20), /must start with 0x/],
    ["non-hex character", "0x" + "zz".repeat(20), /must be hexadecimal/],
    ["too short", "0x" + "ab".repeat(19), /exactly 20 bytes/],
    ["too long", "0x" + "ab".repeat(21), /exactly 20 bytes/],
    ["odd hex length", "0x" + "a".repeat(39), /not a whole number of bytes/],
  ])("rejects %s", (_label, value, match) => {
    expect(() => requireHexBytes(value as string, 20, "F")).toThrow(match as RegExp);
  });

  it("names the field in the error so the admin knows which input is wrong", () => {
    expect(() => requireHexBytes("0xdead", 20, "Result-publisher address"))
      .toThrow(/Result-publisher address/);
  });

  it("reports the actual byte count, not just the expectation", () => {
    expect(() => requireHexBytes("0x" + "ab".repeat(4), 20, "F")).toThrow(/this is 4 bytes/);
  });
});

describe("the three register-form identity fields", () => {
  it("accepts the real shapes", () => {
    expect(requireEligibilityKey(G1)).toBe(G1);
    expect(requireAddress(ADDR, "Result-publisher address")).toBe(ADDR);
    expect(optionalAddress(ADDR, "On-chain ballot sponsor")).toBe(ADDR);
  });

  it("catches the field mix-up: an address pasted into the eligibility key", () => {
    // The exact confusion this guard exists for — a 20-byte address in the 48-byte field
    // would otherwise register fine and make every ballot fail attestation at ingestion.
    expect(() => requireEligibilityKey(ADDR)).toThrow(/exactly 48 bytes/);
  });

  it("catches the reverse mix-up: a G1 key pasted into an address field", () => {
    expect(() => requireAddress(G1, "Result-publisher address")).toThrow(/exactly 20 bytes/);
  });

  it("rejects the zero address for the roles it would be granted to", () => {
    expect(() => requireAddress(ZERO, "Result-publisher address")).toThrow(/zero address/);
    expect(() => optionalAddress(ZERO, "Sponsor")).toThrow(/zero address/);
  });
});

describe("sponsorAddress — necessity follows the backend", () => {
  it("is REQUIRED on the blockchain backend", () => {
    // ElectionBase's constructor reverts on voteProxy == address(0), so a blank sponsor
    // cannot produce a valid chain election. Caught here, before the wallet signs, rather
    // than as a ValueError from the chain adapter afterwards.
    expect(() => sponsorAddress("", "blockchain")).toThrow(/required/);
    expect(() => sponsorAddress("   ", "blockchain")).toThrow(/required/);
    expect(sponsorAddress(ADDR, "blockchain")).toBe(ADDR);
  });

  it("is OPTIONAL on the database backend (blank = open ballot writes)", () => {
    expect(sponsorAddress("", "database")).toBeNull();
    expect(sponsorAddress("   ", "database")).toBeNull();
    expect(sponsorAddress(ADDR, "database")).toBe(ADDR);
  });

  it("stays lenient when the backend is unknown", () => {
    // The capability probe failed. Blocking a legitimate database registration over a
    // failed status fetch would be worse than the chain adapter's own clear error.
    expect(sponsorAddress("", null)).toBeNull();
    expect(sponsorAddress(ADDR, null)).toBe(ADDR);
  });

  it.each(["blockchain", "database", null] as const)(
    "shape-checks a supplied sponsor on every backend (%s)", (store) => {
      expect(() => sponsorAddress("0xabc", store)).toThrow(/exactly 20 bytes/);
      expect(() => sponsorAddress(G1, store)).toThrow(/exactly 20 bytes/);
      expect(() => sponsorAddress(ZERO, store)).toThrow(/zero address/);
    },
  );

  it("names the field so the admin knows which input to fix", () => {
    expect(() => sponsorAddress("", "blockchain")).toThrow(/vote-proxy/);
  });
});
