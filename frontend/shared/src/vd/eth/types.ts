export type Hex = `0x${string}`;

export type ElectionConfigView = {
  electionId: bigint;
  votingStart: bigint;
  votingEnd: bigint;
  selfSubmitFee: bigint;
  numCandidates: number;
  budget: number;
  mode: "exact" | "atMost";      // budget constraint (needed by verifyBallot)
  variant: "A" | "B";            // validity-proof construction (needed by verifyBallot)
  /** The unit the tally counts in. 1 means whole voting weight. Above 1, every
   *  voter's weight was divided by this before aggregation, so the published
   *  totals are in scaled units and will not reconcile with ballot weights. */
  scale: number;
  thresholdN: bigint;
  thresholdT: bigint;
  keyperAddresses: string[];
  pkWR: Hex;
};

export type DkgResultView = {
  pkElection: Hex;
  committeePKs: Hex[];
};

export type Ciphertext = {
  c1: Hex;
  c2: Hex;
};

export type Ballot = {
  pseudonym: Hex; // bytes32
  vk: Hex; // bytes48
  ciphertexts: Ciphertext[]; // bytes96 each
  zkProof: Hex;
  voterSignature: Hex;
  wrAttestation: Hex;
  nonce: number; // attestation re-vote nonce (last-wins ordering; 1 for a first vote)
  /** Eligibility weight this ballot is counted at. The tally multiplies the voter's points
   *  by it, so it is the difference between "80 points" and "6320 points" — but it was
   *  previously visible nowhere, leaving no way to confirm a ballot counted as intended. */
  weight: number;
};

export type EncryptedTally = {
  aggregates: Ciphertext[];
  /** Sum of the admitted ballots' eligibility weights, as held — the "voting power"
   *  behind the result. */
  totalAdmittedWeight: bigint;
  /** The same sum *after* each weight was divided by the election's scale, which is
   *  what the tally actually counted.
   *
   *  These two are equal at scale 1 and the distinction does not arise. Above it they
   *  diverge, and it is `totalScaledWeight` that satisfies "the per-candidate totals
   *  sum to budget x this" — the invariant this comment used to attribute to
   *  `totalAdmittedWeight`, which was true only while scaling did not exist. */
  totalScaledWeight: bigint;
  /** How many ballots the tally actually counted (after duplicates/invalid are excluded). */
  admittedCount: number;
};

export type DecryptionShare = {
  keyperIndex: number;
  submittedAt: bigint;
  shares: Hex[];
  proofs: { e: bigint; z: bigint }[];
  /** geg extension: the raw per-candidate DLEQ proof bytes (geg packs the proof as one
   * hex blob rather than {e,z}); shown in the shares view while live verify is deferred. */
  rawProofs?: Hex[];
};

export type ElectionResult = {
  tally: bigint[];
  keyperIndices: number[];
  /** BSGS plaintext bound = budget · Σ(admitted weights); needed to size the discrete-log
   * table when reproducing a weighted tally (plain totalBallots·budget underflows). */
  bsgsBound: bigint;
};

