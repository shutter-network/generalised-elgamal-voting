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
    // geg carries a *structured* attestation; the dashboard expects one opaque blob.
    // Use the attestation signature as a display stand-in (live verify is deferred).
    wrAttestation: (b.attestation?.signature ?? "0x") as Hex,
  }));
  return { total: BigInt(resp.total), ballots };
}

export async function fetchAggregate(electionId: number): Promise<EncryptedTally | null> {
  const { aggregate } = await api.getAggregate(electionId);
  if (!aggregate) return null;
  return { aggregates: aggregate.aggregates.map((ct) => ({ c1: ct.c1 as Hex, c2: ct.c2 as Hex })) };
}

export async function fetchDecryptionShares(electionId: number): Promise<DecryptionShare[]> {
  const { shares } = await api.getShares(electionId);
  return shares.map((s) => ({
    keyperIndex: s.keyperIndex,
    submittedAt: 0n,
    shares: s.entries.map((e) => e.sigma as Hex),
    // DLEQ {e,z} decode is deferred (verify panels are visual-only for now).
    proofs: s.entries.map(() => ({ e: 0n, z: 0n })),
    rawProofs: s.entries.map((e) => e.proof as Hex),
  }));
}

export async function fetchResult(electionId: number): Promise<ElectionResult | null> {
  const { result } = await api.getResult(electionId);
  if (!result) return null;
  return { tally: result.totals.map((n) => BigInt(n)), keyperIndices: result.keyperIndices };
}
