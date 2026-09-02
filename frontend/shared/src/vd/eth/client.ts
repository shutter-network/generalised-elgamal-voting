/** Data client for the ported voting-dashboard — sources from geg's public read API
 * (`@geg/shared` `api`) instead of an Ethereum contract, and shapes the responses into the
 * voting-dashboard `types.ts` views. Keyed by geg's decimal electionId (number). */
import { api } from "../../api";
import type {
  Ballot,
  DecryptionShare,
  DkgResultView,
  ElectionConfigView,
  ElectionResult,
  EncryptedTally,
  Hex,
} from "./types";

const ZERO32 = ("0x" + "0".repeat(64)) as Hex;

export async function fetchElectionOverview(electionId: number): Promise<{
  config: ElectionConfigView;
  dkg: DkgResultView;
  phase: number;
  cancelled: boolean;
  isDKGFinalized: boolean;
  isResultFinalized: boolean;
  tallyStalled: boolean;
}> {
  const [rec, resultResp] = await Promise.all([api.getElection(electionId), api.getResult(electionId)]);
  const cfg = rec.config;
  const now = Math.floor(Date.now() / 1000);
  // geg has no on-chain phase enum; derive the three the dashboard cares about:
  // <3 pre-voting, 3 voting-open, >=4 post-voting.
  const phase = now >= cfg.votingEnd ? 4 : now >= cfg.votingStart ? 3 : 2;
  const config: ElectionConfigView = {
    electionId: BigInt(cfg.electionId),
    votingStart: BigInt(cfg.votingStart),
    votingEnd: BigInt(cfg.votingEnd),
    selfSubmitFee: 0n,
    numCandidates: cfg.numCandidates,
    budget: cfg.budget,
    mode: cfg.mode,
    variant: cfg.variant,
    scale: cfg.scale ?? 1,
    thresholdN: BigInt(cfg.threshold.n),
    thresholdT: BigInt(cfg.threshold.t),
    keyperAddresses: cfg.keypers.map((k) => k.signingKey),
    pkWR: cfg.eligibilityKey as Hex,
  };
  const dkg: DkgResultView = rec.finalizedKey
    ? { pkElection: rec.finalizedKey.pkElection as Hex, committeePKs: rec.finalizedKey.committeePKs as Hex[] }
    : { pkElection: ZERO32, committeePKs: [] };
  return {
    config,
    dkg,
    phase,
    cancelled: rec.cancelled,
    isDKGFinalized: rec.finalizedKey != null,
    isResultFinalized: resultResp.result != null,
    tallyStalled: rec.tallyStalled ?? false,
  };
}

export async function fetchBallotsPage(
  electionId: number,
  startIndex: number,
  count: number,
): Promise<{ total: bigint; ballots: Ballot[] }> {
  const resp = await api.listBallots(electionId, Math.max(0, startIndex), count);
  const ballots: Ballot[] = (resp.ballots as any[]).map((b) => ({
    pseudonym: b.pseudonym as Hex,
    vk: b.vk as Hex,
    ciphertexts: (b.ciphertexts ?? []).map((ct: any) => ({ c1: ct.c1 as Hex, c2: ct.c2 as Hex })),
    zkProof: b.zkProof as Hex,
    voterSignature: b.voterSignature as Hex,
    // geg's attestation is structured (scheme, weight, nonce, 80-byte R‖s sig); the SDK's WR
    // verifier callback only receives one opaque blob, so pack everything the scheme-
    // directed verifier needs into it: scheme(1) ‖ weight(32 BE) ‖ nonce(32 BE) ‖ signature(80).
    wrAttestation: packWrAttestation(b.attestation?.scheme, b.attestation?.weight, b.attestation?.nonce, b.attestation?.signature),
    nonce: Number(b.attestation?.nonce ?? 1),
    weight: Number(b.attestation?.weight ?? 1),
  }));
  return { total: BigInt(resp.total), ballots };
}

/** Pack geg's structured attestation into the single `att` blob the WR verifier reads:
 * `scheme(1) ‖ weight(32-byte BE) ‖ nonce(32-byte BE) ‖ signature(80 = R‖s)`. scheme byte:
 * 0x01 = ATTESTATION_V1, 0x00 = LEGACY (weightless). Mirrors geg core `verify_attestation`. */
function packWrAttestation(scheme: string | undefined, weight: number | undefined, nonce: number | undefined, sig: string | undefined): Hex {
  const schemeByte = scheme === "LEGACY" ? "00" : "01";
  const weightHex = BigInt(weight ?? 1).toString(16).padStart(64, "0");
  const nonceHex = BigInt(nonce ?? 1).toString(16).padStart(64, "0");
  const sigHex = (sig ?? "0x").replace(/^0x/, "");
  return ("0x" + schemeByte + weightHex + nonceHex + sigHex) as Hex;
}

export async function fetchAggregate(electionId: number): Promise<EncryptedTally | null> {
  const { aggregate } = await api.getAggregate(electionId);
  if (!aggregate) return null;
  return {
    aggregates: aggregate.aggregates.map((ct: any) => ({ c1: ct.c1 as Hex, c2: ct.c2 as Hex })),
    totalAdmittedWeight: BigInt(aggregate.totalAdmittedWeight ?? 0),
    // Mirrors geg's decoder, which defaults the scaled total to the raw one when the
    // field is absent: they are equal by construction at scale 1, so an artifact
    // written before scaling existed decodes correctly. Defaulting to 0 would make
    // an unscaled election look like it counted nothing.
    totalScaledWeight: BigInt(
      aggregate.totalScaledWeight ?? aggregate.totalAdmittedWeight ?? 0,
    ),
    admittedCount: (aggregate.admitted ?? []).length,
  };
}

export async function fetchDecryptionShares(electionId: number): Promise<DecryptionShare[]> {
  const { shares } = await api.getShares(electionId);
  return shares.map((s) => ({
    keyperIndex: s.keyperIndex,
    submittedAt: 0n,
    shares: s.entries.map((e) => e.sigma as Hex),
    // geg packs each DLEQ proof as a 64-byte big-endian blob `e(32) ‖ z(32)`
    // (crypto/params.py DLEQ_BYTES, proofs.encode_dleq); decode it back to {e, z}
    // so the shares/result verification fixtures carry the real challenge + response.
    proofs: s.entries.map((e) => decodeDleq(e.proof as Hex)),
    rawProofs: s.entries.map((e) => e.proof as Hex),
  }));
}

/** Split geg's 64-byte DLEQ blob (0x-hex, big-endian `e(32)‖z(32)`) into scalars. */
function decodeDleq(proof: Hex): { e: bigint; z: bigint } {
  const hex = proof.replace(/^0x/, "").padStart(128, "0");
  return { e: BigInt("0x" + hex.slice(0, 64)), z: BigInt("0x" + hex.slice(64, 128)) };
}

export async function fetchResult(electionId: number): Promise<ElectionResult | null> {
  const { result } = await api.getResult(electionId);
  if (!result) return null;
  return { tally: result.totals.map((n) => BigInt(n)), keyperIndices: result.keyperIndices, bsgsBound: BigInt(result.bsgsBound) };
}
