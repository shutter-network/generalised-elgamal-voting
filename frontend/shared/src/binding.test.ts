/** Cross-language parity for the ballot<->credential binding message.
 *
 * The voter signs this in the browser; a keyper verifies it in Python. The SDK
 * keeps `Transcript.preimage()` private, so `binding.ts` rebuilds the transcript
 * layout rather than reusing it — which means the two implementations agree only
 * as far as something checks. That is this file.
 *
 * A one-byte disagreement is not a subtle bug: every ballot the app produces is
 * excluded as INVALID_ATTESTATION, which presents as an eligibility failure and
 * points nowhere near the encoding that caused it.
 *
 * Vectors come from geg's own `crypto/binding.py` via
 * `scripts/gen_vectors.py binding`, so this asserts agreement with the protocol
 * rather than agreement with ourselves.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { attestationDigest, bindingMessage } from "./binding";
import { hexToBytes } from "./hex";
import type { AttestationJson } from "./types";

type Case = {
  name: string;
  attestation: AttestationJson;
  ballotDigest: `0x${string}`;
  attestationDigest: `0x${string}`;
  bindingMessage: `0x${string}`;
  voterAttestationSignature: `0x${string}`;
};

const fixture = JSON.parse(
  readFileSync(
    join(__dirname, "../../../tests/vectors/binding/binding_message.json"),
    "utf8",
  ),
) as {
  inputs: { electionId: `0x${string}`; pseudonym: `0x${string}`; vk: `0x${string}` };
  cases: Case[];
};

const hex = (b: Uint8Array) =>
  `0x${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`;

function build(c: Case): Uint8Array {
  return bindingMessage({
    electionId: hexToBytes(fixture.inputs.electionId),
    pseudonym: hexToBytes(fixture.inputs.pseudonym),
    vk: hexToBytes(fixture.inputs.vk),
    ballotDigest: hexToBytes(c.ballotDigest),
    attestation: c.attestation,
  });
}

describe("bindingMessage — parity with geg's Python", () => {
  it("has vectors covering both credential schemes", () => {
    // Guards the fixture: a V1-only corpus would prove nothing about the legacy
    // branch, which uses an entirely different (undomained) preimage.
    const schemes = new Set(fixture.cases.map((c) => c.attestation.scheme));
    expect(schemes.has("ATTESTATION_V1")).toBe(true);
    expect(schemes.has("ATTESTATION_LEGACY")).toBe(true);
  });

  it.each(fixture.cases.map((c) => [c.name, c] as const))(
    "reproduces the attestation digest for %s",
    (_name, c) => {
      expect(hex(attestationDigest(c.attestation))).toBe(c.attestationDigest);
    },
  );

  it.each(fixture.cases.map((c) => [c.name, c] as const))(
    "reproduces the binding message for %s",
    (_name, c) => {
      expect(hex(build(c))).toBe(c.bindingMessage);
    },
  );

  // Large nonces are not exotic — sx issues a unix timestamp — and a truncating
  // scalar encoding would pass every small-value case above. A timestamp alone is
  // not enough to catch it: 1.7e9 still fits in 32 bits, so the corpus carries a
  // value past 2^32 as well, and both are asserted here.
  it.each([
    ["timestamp-sized", 1_000_000_000],
    ["beyond 32 bits", 2 ** 32],
  ])("handles a %s nonce", (_label, floor) => {
    const big = fixture.cases.find((c) => (c.attestation.nonce ?? 0) > floor);
    expect(big).toBeDefined();
    expect(hex(build(big!))).toBe(big!.bindingMessage);
  });
});

describe("bindingMessage — what it commits to", () => {
  const base = fixture.cases[0];

  const withAttestation = (over: Partial<AttestationJson>) =>
    hex(build({ ...base, attestation: { ...base.attestation, ...over } }));

  it("changes when the weight changes", () => {
    expect(withAttestation({ weight: base.attestation.weight + 1 })).not.toBe(
      base.bindingMessage,
    );
  });

  it("changes when the nonce changes — the re-vote arbiter", () => {
    expect(withAttestation({ nonce: (base.attestation.nonce ?? 0) + 1 })).not.toBe(
      base.bindingMessage,
    );
  });

  it("changes when the issuer's signature changes", () => {
    expect(withAttestation({ signature: `0x${"99".repeat(80)}` })).not.toBe(
      base.bindingMessage,
    );
  });

  it("changes when the ballot changes", () => {
    expect(hex(build({ ...base, ballotDigest: `0x${"99".repeat(32)}` }))).not.toBe(
      base.bindingMessage,
    );
  });

  it("separates the two credential schemes", () => {
    // Same fields, different scheme: must not collide.
    expect(withAttestation({ scheme: "ATTESTATION_LEGACY" })).not.toBe(
      withAttestation({ scheme: "ATTESTATION_V1" }),
    );
  });
});

describe("bindingMessage — rejections", () => {
  const base = fixture.cases[0];

  it("refuses an unknown scheme rather than signing something unverifiable", () => {
    expect(() =>
      build({ ...base, attestation: { ...base.attestation, scheme: "ATTESTATION_V99" } }),
    ).toThrow(/unknown attestation scheme/);
  });

  it("refuses an empty issuer signature", () => {
    expect(() =>
      build({ ...base, attestation: { ...base.attestation, signature: "0x" } }),
    ).toThrow(/must not be empty/);
  });

  it.each([
    ["electionId", 32],
    ["pseudonym", 32],
    ["vk", 48],
    ["ballotDigest", 32],
  ])("refuses a wrong-length %s", (field, len) => {
    const args = {
      electionId: hexToBytes(fixture.inputs.electionId),
      pseudonym: hexToBytes(fixture.inputs.pseudonym),
      vk: hexToBytes(fixture.inputs.vk),
      ballotDigest: hexToBytes(base.ballotDigest),
      attestation: base.attestation,
    };
    expect(() =>
      bindingMessage({ ...args, [field]: new Uint8Array(len - 1) } as never),
    ).toThrow(new RegExp(`${field} must be`));
  });
});
