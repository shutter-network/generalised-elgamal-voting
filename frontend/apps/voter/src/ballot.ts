/** Client-side ballot construction + submission.
 *
 * Uses `@shutter-network/urban-verified-crypto` (the TS origin the Python crypto
 * byte-matches) to build the encrypted ballot entirely in the browser — plaintext
 * votes and randomness never leave this device. The eligibility attestation comes from
 * the (pluggable, dummy) eligibility service and is attached as the geg wire's
 * *structured* `attestation` field.
 *
 * Attestation note: the SDK's `wrAttestation` is opaque bytes NOT covered by the signed
 * `canonicalBallotMessage`, whereas the geg wire ballot carries a structured attestation
 * the gateway/tally verify. So we pass an empty placeholder to `buildBallot` and attach
 * the real structured attestation when assembling the wire envelope.
 *
 * Because the SDK's ballot signature cannot be extended to cover that attestation, the
 * envelope carries a second signature under the same voter key — `voterAttestationSignature`
 * — over the ballot digest and the credential together. Without it the voter commits to no
 * particular `weight` or `nonce`, and `nonce` is what orders their re-votes. */

import {
  G2Point,
  buildBallot,
  canonicalBallotMessage,
  encodeSchnorr,
  initCurves,
  schnorrKeygen,
  schnorrSign,
  type BallotInputs,
} from "@shutter-network/urban-verified-crypto";
import {
  attest,
  bindingMessage,
  bytesToHex,
  eidToBareHex,
  eidToHex,
  hexToBytes,
  submitBallot,
  type BallotJson,
  type ElectionConfig,
} from "@geg/shared";
import { keccak256 } from "viem";
import type { Hex } from "viem";

/** The chain-free EIP-191 challenge the wallet signs — byte-identical to the eligibility
 * service's `challenge_message` (see eligibility.py), so the service can `ecrecover` it. */
function challengeMessage(eidHex: string, vkHex: string): string {
  return `GEG eligibility attestation\nelectionId: ${eidHex}\nvk: ${vkHex}`;
}

let curvesReady: Promise<void> | null = null;
/** Load blst.wasm + init the curve library once (idempotent). */
export function ensureCurves(): Promise<void> {
  if (!curvesReady) curvesReady = initCurves();
  return curvesReady;
}

export interface CastVoteArgs {
  config: ElectionConfig;
  pkElectionHex: string; // finalizedKey.pkElection (0x-hex, 96-byte compressed G2)
  votes: number[]; // length == numCandidates
  /** EIP-191 personal-sign from the connected wallet (chain-agnostic). */
  signMessage: (message: string) => Promise<Hex>;
  onStage?: (msg: string) => void;
}

export async function castVote(args: CastVoteArgs): Promise<{ sequenceNumber: number }> {
  await ensureCurves();
  const { config, pkElectionHex, votes, signMessage, onStage } = args;

  const eidHex = eidToHex(config.electionId);
  const eidBytes = hexToBytes(eidHex);
  const mpk = G2Point.fromBytes(hexToBytes(pkElectionHex));

  // Ephemeral voter Schnorr key. The wallet personal-signs the challenge over
  // (electionId, vk); the eligibility service recovers the wallet, derives a stable
  // per-wallet pseudonym, and returns it + the attestation. The pseudonym is
  // server-owned (one wallet, one vote); we build the ballot with exactly it.
  const { sk, vk } = schnorrKeygen();
  const vkHex = bytesToHex(vk.toBytes());
  const signature = await signMessage(challengeMessage(eidHex, vkHex));
  onStage?.("Requesting eligibility attestation…");
  const { attestation, pseudonym } = await attest({ electionId: eidHex, vk: vkHex, signature });
  const pseudonymBytes = hexToBytes(pseudonym);

  onStage?.("Building ballot");
  const inputs: BallotInputs = buildBallot({
    mpk,
    electionId: eidBytes,
    pseudonym: pseudonymBytes,
    sk,
    vk,
    votes: votes.map((v) => BigInt(v)),
    params: {
      numCandidates: config.numCandidates,
      budget: config.budget,
      mode: config.mode,
      variant: config.variant,
    },
    wrAttestation: new Uint8Array(0), // placeholder; not signed, not read by geg
  });

  // Bind the ballot to the credential it was cast with.
  //
  // `voterSignature` covers (electionId, pseudonym, ciphertexts, zkProof) and
  // says nothing about `weight` or `nonce`. Since `nonce` decides which of a
  // voter's re-votes counts, a signature over the ballot alone leaves whoever
  // pairs the two free to choose. This second signature — same key, both digests
  // — is what makes the pairing the voter's, and admission rejects a ballot
  // whose binding does not verify.
  onStage?.("Signing ballot + attestation");
  const ballotDigest = hexToBytes(
    keccak256(
      canonicalBallotMessage({
        electionId: eidBytes,
        pseudonym: inputs.pseudonym,
        ciphertexts: inputs.ciphertexts,
        zkProof: inputs.zkProof,
      }),
    ),
  );
  const voterAttestationSignature = bytesToHex(
    encodeSchnorr(
      schnorrSign(
        sk,
        vk,
        bindingMessage({
          electionId: eidBytes,
          pseudonym: inputs.pseudonym,
          vk: inputs.vk,
          ballotDigest,
          attestation,
        }),
      ),
    ),
  );

  const ballot: BallotJson = {
    electionId: eidHex,
    pseudonym: bytesToHex(inputs.pseudonym),
    vk: bytesToHex(inputs.vk),
    ciphertexts: inputs.ciphertexts.map(([c1, c2]) => ({ c1: bytesToHex(c1), c2: bytesToHex(c2) })),
    zkProof: bytesToHex(inputs.zkProof),
    voterSignature: bytesToHex(inputs.voterSignature),
    attestation,
    voterAttestationSignature,
  };

  return submitBallot(eidToBareHex(config.electionId), ballot);
}
