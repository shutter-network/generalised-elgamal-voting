/* On-demand, in-browser cryptographic verification of the four public artifacts —
 * ballot, aggregate, decryption shares, result. A faithful port of the logic validated
 * end-to-end against live geg data (weighted + weight-1), using the same SDK the voter's
 * ballot builder uses (`@shutter-network/urban-verified-crypto`). The SDK (+ blst.wasm) is
 * loaded lazily on first use so it stays out of the main bundle.
 *
 * geg-specific adaptations over the stock Munich verification:
 *   - WR attestation is scheme-directed: ATTESTATION_V1 (domain-separated transcript over
 *     electionId,pseudonym,vk,weight,nonce) or LEGACY (weightless keccak, weight 1). The
 *     adapter packs `scheme(1)‖weight(32 BE)‖nonce(32 BE)‖R(48)‖s(32)` into `wrAttestation`.
 *   - Aggregate is the weighted sum `Σ weightᵢ·ctᵢ` (scalarMulCt then sumCts).
 *   - Result BSGS bound is the published `bsgsBound` (= budget · Σ admitted weights). */
import { keccak256 } from "viem";
import { Buffer } from "buffer";

export type VerifyResult = { ok: true } | { ok: false; reason: string };

// ── lazy SDK + curve init ────────────────────────────────────────────────
let _sdk: any = null;
async function sdk(): Promise<any> {
  if (!_sdk) {
    _sdk = await import("@shutter-network/urban-verified-crypto");
    await _sdk.initCurves();
  }
  return _sdk;
}

// ── byte helpers ─────────────────────────────────────────────────────────
const fromHex = (h: string) => Uint8Array.from(Buffer.from(String(h).replace(/^0x/, ""), "hex"));
const electionId32 = (id: bigint | number | string) => fromHex(BigInt(id).toString(16).padStart(64, "0"));
const u32be = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const scalar32 = (w: bigint) => { const b = Buffer.alloc(32); let x = BigInt(w); for (let i = 31; i >= 0 && x > 0n; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };

// ── WR attestation: scheme-directed verifier (mirrors geg core verify_attestation) ──
function tlv(parts: Buffer[], tag: string, val: Uint8Array) {
  const tb = Buffer.from(tag, "utf8");
  parts.push(u32be(tb.length), tb, u32be(val.length), Buffer.from(val));
}
function v1Digest(eid: Uint8Array, ps: Uint8Array, vk: Uint8Array, weight: bigint, nonce: bigint): Uint8Array {
  const p: Buffer[] = [Buffer.from("SHUTTER-VOTE-ATTEST-v1", "utf8")];
  tlv(p, "attest:electionId", eid);
  tlv(p, "attest:pseudonym", ps);
  tlv(p, "attest:vk", vk);
  tlv(p, "attest:weight", scalar32(weight));
  tlv(p, "attest:nonce", scalar32(nonce));
  return fromHex(keccak256(Buffer.concat(p) as any));
}
const legacyDigest = (eid: Uint8Array, ps: Uint8Array, vk: Uint8Array) =>
  fromHex(keccak256(Buffer.concat([Buffer.from(eid), Buffer.from(ps), Buffer.from(vk)]) as any));

/** Returns a WR-verifier callback for verifyBallot, reading the packed att blob
 * `scheme(1)‖weight(32 BE)‖nonce(32 BE)‖sig(80)`. */
function makeWrVerifier(S: any, pkWr: Uint8Array) {
  const wrVk = S.G1Point.fromBytes(pkWr);
  return (eid: Uint8Array, ps: Uint8Array, vk: Uint8Array, att: Uint8Array): boolean => {
    if (eid.length !== 32 || ps.length !== 32 || vk.length !== 48) return false;
    try {
      const scheme = att[0];
      let w = 0n; for (let i = 1; i < 33; i++) w = (w << 8n) + BigInt(att[i]);
      let n = 0n; for (let i = 33; i < 65; i++) n = (n << 8n) + BigInt(att[i]);
      if (w < 1n || (scheme !== 1 && w !== 1n)) return false;
      if (scheme === 1 && n < 1n) return false;
      const sig = att.subarray(65);
      let s = 0n; for (let i = 48; i < 80; i++) s = (s << 8n) + BigInt(sig[i]);
      const msg = scheme === 1 ? v1Digest(eid, ps, vk, w, n) : legacyDigest(eid, ps, vk);
      return S.schnorrVerify(wrVk, msg, { R: S.G1Point.fromBytes(sig.subarray(0, 48)), s });
    } catch { return false; }
  };
}
const attWeight = (attHex: string): bigint => { const a = fromHex(attHex); let w = 0n; for (let i = 1; i < 33; i++) w = (w << 8n) + BigInt(a[i]); return w; };

// ── shared input shapes (subset of the dashboard's view types) ───────────
type Ct = { c1: string; c2: string };
export type VBallot = { pseudonym: string; vk: string; ciphertexts: Ct[]; zkProof: string; voterSignature: string; wrAttestation: string };
type VConfig = { electionId: bigint; numCandidates: number; budget: number; mode: "exact" | "atMost"; variant: "A" | "B"; pkWR: string };
type VShare = { keyperIndex: number; shares: string[]; proofs: { e: bigint; z: bigint }[] };

// ── 1. ballot ─────────────────────────────────────────────────────────────
export async function verifyBallotLocal(ballot: VBallot, cfg: VConfig, mpkHex: string): Promise<VerifyResult> {
  const S = await sdk();
  const res = S.verifyBallot(
    {
      electionId: electionId32(cfg.electionId), pseudonym: fromHex(ballot.pseudonym), vk: fromHex(ballot.vk),
      ciphertexts: ballot.ciphertexts.map((c) => [fromHex(c.c1), fromHex(c.c2)]),
      zkProof: fromHex(ballot.zkProof), voterSignature: fromHex(ballot.voterSignature), wrAttestation: fromHex(ballot.wrAttestation),
    },
    { numCandidates: cfg.numCandidates, budget: cfg.budget, mode: cfg.mode, variant: cfg.variant },
    S.G2Point.fromBytes(fromHex(mpkHex)),
    makeWrVerifier(S, fromHex(cfg.pkWR)),
  );
  return res.ok ? { ok: true } : { ok: false, reason: res.reason ?? "invalid" };
}

// ── 2. aggregate (weighted homomorphic sum) ─────────────────────────────────
export async function verifyAggregateLocal(cfg: VConfig, mpkHex: string, aggregate: Ct[], ballots: VBallot[]): Promise<VerifyResult> {
  const S = await sdk();
  const wr = makeWrVerifier(S, fromHex(cfg.pkWR));
  const g2 = (h: string) => S.G2Point.fromBytes(fromHex(h));
  const valid = ballots.filter((b) => S.verifyBallot(
    { electionId: electionId32(cfg.electionId), pseudonym: fromHex(b.pseudonym), vk: fromHex(b.vk),
      ciphertexts: b.ciphertexts.map((c) => [fromHex(c.c1), fromHex(c.c2)]),
      zkProof: fromHex(b.zkProof), voterSignature: fromHex(b.voterSignature), wrAttestation: fromHex(b.wrAttestation) },
    { numCandidates: cfg.numCandidates, budget: cfg.budget, mode: cfg.mode, variant: cfg.variant },
    g2(mpkHex), wr,
  ).ok);
  for (let j = 0; j < cfg.numCandidates; j++) {
    const sum = S.sumCts(valid.map((b) => S.scalarMulCt(attWeight(b.wrAttestation), { c1: g2(b.ciphertexts[j].c1), c2: g2(b.ciphertexts[j].c2) })));
    const pub = { c1: g2(aggregate[j].c1), c2: g2(aggregate[j].c2) };
    if (!(sum.c1.equals(pub.c1) && sum.c2.equals(pub.c2))) return { ok: false, reason: `candidate ${j}: sum ≠ published aggregate` };
  }
  return { ok: true };
}

// ── 3. decryption shares (DLEQ) ─────────────────────────────────────────────
function decryptTranscript(S: any, eid: Uint8Array, j: number) {
  const t = new S.Transcript("SHUTTER-VOTE-DECRYPT-v1");
  t.append("electionId", eid);
  t.append("candidate", new Uint8Array([(j >> 8) & 255, j & 255]));
  return t;
}
export type ShareVerdict = { keyperIndex: number; candidate: number; ok: boolean };
export async function verifySharesLocal(electionId: bigint, numCandidates: number, aggregate: Ct[], committeePks: string[], shares: VShare[]): Promise<{ ok: boolean; verdicts: ShareVerdict[] }> {
  const S = await sdk();
  const eid = electionId32(electionId);
  const g2 = (h: string) => S.G2Point.fromBytes(fromHex(h));
  const verdicts: ShareVerdict[] = [];
  let ok = true;
  for (const s of shares) {
    const member = s.keyperIndex - 1; // geg keyperIndex is 1-based; committee is 0-based
    const pk = g2(committeePks[member]);
    for (let j = 0; j < numCandidates; j++) {
      const ct = { c1: g2(aggregate[j].c1), c2: g2(aggregate[j].c2) };
      const share = { keyperIndex: s.keyperIndex, sigma: g2(s.shares[j]), proof: { e: BigInt(s.proofs[j].e), z: BigInt(s.proofs[j].z) } };
      const valid = S.verifyDecryptionShare(ct, share, pk, decryptTranscript(S, eid, j));
      if (!valid) ok = false;
      verdicts.push({ keyperIndex: s.keyperIndex, candidate: j, ok: valid });
    }
  }
  return { ok, verdicts };
}

// ── 4. result (threshold decrypt + BSGS, compared to the published tally) ───
export async function verifyResultLocal(
  electionId: bigint, numCandidates: number, quorum: number, bsgsBound: bigint,
  aggregate: Ct[], committeePks: string[], shares: VShare[], tally: bigint[],
): Promise<VerifyResult> {
  const S = await sdk();
  const eid = electionId32(electionId);
  const g2 = (h: string) => S.G2Point.fromBytes(fromHex(h));
  const table = S.buildBabyStepTable(BigInt(bsgsBound));
  for (let j = 0; j < numCandidates; j++) {
    const ct = { c1: g2(aggregate[j].c1), c2: g2(aggregate[j].c2) };
    const valid: any[] = [];
    for (const s of shares) {
      const member = s.keyperIndex - 1;
      const share = { keyperIndex: s.keyperIndex, sigma: g2(s.shares[j]), proof: { e: BigInt(s.proofs[j].e), z: BigInt(s.proofs[j].z) } };
      if (S.verifyDecryptionShare(ct, share, g2(committeePks[member]), decryptTranscript(S, eid, j))) valid.push(share);
      if (valid.length >= quorum) break;
    }
    if (valid.length < quorum) return { ok: false, reason: `candidate ${j}: only ${valid.length} valid shares (need ${quorum})` };
    const total = S.recoverDiscreteLogWithTable(S.combineShares(valid, valid.map((sh) => BigInt(sh.keyperIndex)), ct), table);
    if (total !== BigInt(tally[j])) return { ok: false, reason: `candidate ${j}: recovered ${total} ≠ published ${tally[j]}` };
  }
  return { ok: true };
}
