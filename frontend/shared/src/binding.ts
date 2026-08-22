/** The voter's binding of a ballot to the credential it was cast with.
 *
 * The credential already names this voter — admission checks
 * `att.pseudonym === ballot.pseudonym` and `att.vk === ballot.vk`, and the ballot
 * signature is verified against that same `vk`. What nothing voter-signed covered
 * is *which* of that voter's credentials this ballot was cast with:
 * `canonicalBallotMessage` spans `(electionId, pseudonym, ciphertexts, zkProof)`
 * and neither `weight` nor `nonce`. Since `nonce` orders re-votes, whoever pairs a
 * ballot with a credential could otherwise choose which of a voter's ballots wins.
 *
 * Byte-identical to `geg/crypto/binding.py`, and pinned against vectors generated
 * by it. If the two ever disagree, every ballot this app produces is excluded as
 * INVALID_ATTESTATION — a failure that reads as an eligibility problem and gives
 * no hint that it is really an encoding one.
 *
 * ## Why the transcript is rebuilt here
 *
 * The SDK exports `Transcript`, but only its `challenge()` — `preimage()` and the
 * accumulated parts are private, so it cannot produce the bytes this message
 * hashes. The layout is reproduced below rather than worked around: it is four
 * lines, it is fully specified, and the cross-language vectors are what actually
 * hold it in place.
 */

import { keccak256 } from "viem";
import type { Hex } from "viem";
import { hexToBytes } from "./hex";
import type { AttestationJson } from "./types";

/** Transcript label; distinct from the ballot and attestation labels so a
 * signature over one can never be presented as a signature over another. */
const BINDING_LABEL = "SHUTTER-VOTE-BINDING-v1";
const ATTESTATION_LABEL = "SHUTTER-VOTE-ATTEST-v1";

/** Credential schemes, as scalars. Bound explicitly so a LEGACY credential and a
 * V1 one over otherwise identical fields cannot produce the same binding. */
const SCHEME_CODES: Record<string, bigint> = {
  ATTESTATION_V1: 1n,
  ATTESTATION_LEGACY: 2n,
};

const enc = new TextEncoder();

function u32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/** 32-byte big-endian, matching `params.scalar_to_bytes`. */
function scalarToBytes(s: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = s;
  for (let i = 31; i >= 0 && v > 0n; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** The append-only, length-prefixed transcript of `crypto/transcript.py`.
 * Length prefixes are what make concatenation injective — without them
 * `("ab", "c")` and `("a", "bc")` would hash alike. */
class Preimage {
  private readonly parts: Uint8Array[];

  constructor(label: string) {
    this.parts = [enc.encode(label)];
  }

  append(tag: string, value: Uint8Array): this {
    const tb = enc.encode(tag);
    this.parts.push(u32be(tb.length), tb, u32be(value.length), value);
    return this;
  }

  appendScalar(tag: string, s: bigint): this {
    return this.append(tag, scalarToBytes(s));
  }

  bytes(): Uint8Array {
    const total = this.parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let at = 0;
    for (const p of this.parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }
}

function requireLen(name: string, b: Uint8Array, n: number): Uint8Array {
  if (b.length !== n) throw new Error(`${name} must be ${n} bytes (got ${b.length})`);
  return b;
}

/** The credential's own signed digest — the same one the eligibility service
 * signed, not a second definition of it. */
export function attestationDigest(att: AttestationJson): Uint8Array {
  const electionId = requireLen("electionId", hexToBytes(att.electionId), 32);
  const pseudonym = requireLen("pseudonym", hexToBytes(att.pseudonym), 32);
  const vk = requireLen("vk", hexToBytes(att.vk), 48);
  const scheme = att.scheme ?? "ATTESTATION_V1";

  if (scheme === "ATTESTATION_LEGACY") {
    // Weightless: a bare keccak concatenation with no domain separator, kept for
    // interop. Deliberately *not* the V1 transcript.
    const flat = new Uint8Array(32 + 32 + 48);
    flat.set(electionId, 0);
    flat.set(pseudonym, 32);
    flat.set(vk, 64);
    return hexToBytes(keccak256(flat));
  }

  const nonce = att.nonce ?? 0;
  const t = new Preimage(ATTESTATION_LABEL)
    .append("attest:electionId", electionId)
    .append("attest:pseudonym", pseudonym)
    .append("attest:vk", vk)
    .appendScalar("attest:weight", BigInt(att.weight))
    .appendScalar("attest:nonce", BigInt(nonce));
  return hexToBytes(keccak256(t.bytes()));
}

export interface BindingMessageArgs {
  electionId: Uint8Array;
  pseudonym: Uint8Array;
  vk: Uint8Array;
  /** `keccak256(canonicalBallotMessage(...))` — the SDK builds the preimage. */
  ballotDigest: Uint8Array;
  attestation: AttestationJson;
}

/** The keccak256 digest the voter signs to bind one ballot to one credential. */
export function bindingMessage(args: BindingMessageArgs): Uint8Array {
  const scheme = args.attestation.scheme ?? "ATTESTATION_V1";
  const code = SCHEME_CODES[scheme];
  if (code === undefined) throw new Error(`unknown attestation scheme: ${scheme}`);

  const eligSig = hexToBytes(args.attestation.signature);
  if (eligSig.length === 0) throw new Error("eligibilitySignature must not be empty");

  const t = new Preimage(BINDING_LABEL)
    .append("bind:electionId", requireLen("electionId", args.electionId, 32))
    .append("bind:pseudonym", requireLen("pseudonym", args.pseudonym, 32))
    .append("bind:vk", requireLen("vk", args.vk, 48))
    .append("bind:ballot", requireLen("ballotDigest", args.ballotDigest, 32))
    .appendScalar("bind:scheme", code)
    // The credential's contents *and* the issuer's signature over them, so the
    // voter commits to the exact instance rather than to fields that a second,
    // differently-signed credential could also satisfy.
    .append("bind:attestation", attestationDigest(args.attestation))
    .append("bind:eligSig", eligSig);
  return hexToBytes(keccak256(t.bytes()));
}

/** Convenience for callers holding hex rather than bytes. */
export function bindingMessageHex(args: {
  electionId: Hex;
  pseudonym: Hex;
  vk: Hex;
  ballotDigest: Hex;
  attestation: AttestationJson;
}): Uint8Array {
  return bindingMessage({
    electionId: hexToBytes(args.electionId),
    pseudonym: hexToBytes(args.pseudonym),
    vk: hexToBytes(args.vk),
    ballotDigest: hexToBytes(args.ballotDigest),
    attestation: args.attestation,
  });
}
