export type Hex = `0x${string}`;

export type ElectionConfigView = {
  electionId: bigint;
  votingStart: bigint;
  votingEnd: bigint;
  selfSubmitFee: bigint;
  numCandidates: number;
  budget: number;
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
};

export type EncryptedTally = {
  aggregates: Ciphertext[];
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

