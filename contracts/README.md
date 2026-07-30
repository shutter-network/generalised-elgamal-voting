# Shutter Voting Contracts

This directory contains the Foundry contracts for the Shutter ElGamal voting bulletin board.

The contract scope covers:

- `KeyperSet` immutable membership and threshold configuration
- `ElectionRegistry` deployment and indexing of elections
- `Election` DKG result publication
- ballot submission with full on-chain proof storage
- decryption share submission
- tally finalization
- post-completion fee withdrawal
- stable interfaces for integration
- deployment script and test coverage

## Dependencies

The Foundry dependencies (`openzeppelin-contracts`, `forge-std`) are **git
submodules** under `lib/`, pinned to exact versions. They are **not** committed as
files, so fetch them before building:

```shell
# when cloning the repo:
git clone --recurse-submodules <repo-url>

# or, if you already cloned without submodules:
git submodule update --init
```

`foundry.toml` sets `offline = true`, so once the submodules are checked out the
build does no further network access.

## Repository Layout

### Core contracts

- `src/KeyperSet.sol`
- `src/ElectionRegistry.sol`
- `src/Election.sol`
- `src/election/ElectionBase.sol`
- `src/election/ElectionDKG.sol`
- `src/election/ElectionVoting.sol`
- `src/election/ElectionTally.sol`
- `src/election/ElectionDecryption.sol`
- `src/election/ElectionAdmin.sol`
- `src/VotingTypes.sol`

### Interfaces

- `src/interfaces/IKeyperSet.sol`
- `src/interfaces/IElection.sol`
- `src/interfaces/IElectionRegistry.sol`

### Scripts

- `script/Deploy.s.sol`
- `script/DeployAndPublishLocal.s.sol`
- `script/PublishElection.s.sol`

### Tests

- `test/Scaffold.t.sol`
- `test/KeyperSet.t.sol`
- `test/ElectionRegistry.t.sol`
- `test/ElectionDKG.t.sol`
- `test/ElectionVote.t.sol`
- `test/ElectionTally.t.sol`
- `test/ElectionAdmin.t.sol`
- `test/ElectionInvariant.t.sol`

## Contract Overview

### `KeyperSet`

`KeyperSet` is the immutable keyper committee contract. It is used by elections to determine membership, threshold, and each member's HTTP URL.

Implemented behavior:

- constructor-time member, per-member **URL**, and threshold configuration
- URLs are **required** and 1:1 with members (reverts `URLsLengthMismatch` otherwise)
- duplicate member rejection
- zero-address rejection
- threshold validation
- getters and membership checks

Available read methods include:

- `getNumMembers`
- `getMember`
- `getMembers`
- `getURLs` — per-member URLs, index-aligned with members (surfaced in `getElection()` as `keyperURLs`)
- `getMemberIndex`
- `getThreshold`
- `isMember`

### `ElectionRegistry`

`ElectionRegistry` is the admin-gated factory and index for `Election` instances.

Implemented behavior:

- `DEFAULT_ADMIN_ROLE`-gated `publishElection`
- sequential `electionId` assignment
- address lookup by election id
- paged lookup through `getElections`
- `ElectionCreated` event emission

`publishElection` validates that the supplied `KeyperSet` is:

- non-empty
- configured with a non-zero threshold no greater than the keyper count

### `Election`

`Election` is the per-election bulletin board contract.

Immutable election configuration (generalised — beyond the original Munich set):

- `electionId` (registry-assigned, sequential)
- `keyperSet`
- `votingStart`, `votingEnd`, `tallyDeadline`
- `selfSubmitFee`
- `numCandidates`, `budget`
- `mode`, `variant`, `weighted`, `maxWeight`, `duplicatePolicy`, `protocolVersion`
- `pkWR` (eligibility public key)
- `adminAddr`, `tallyAggregator`, `voteProxy`

Configured roles:

- `DEFAULT_ADMIN_ROLE`
- `TALLY_AGGREGATOR_ROLE`
- `VOTE_PROXY_ROLE`

#### DKG result publication

Implemented behavior:

- `voteDKGResult(bytes pkElection, bytes[] committeePKs)` — authorized by `msg.sender`
- `voteDKGResultSigned(bytes pkElection, bytes[] committeePKs, bytes keyperSig)` — **meta-tx**: the keyper content-signs (EIP-191), any relayer sends the tx paying gas, and the contract `ECDSA.recover`s the keyper as the on-chain author (so keypers need no gas)
- keyper-only participation (member of the `KeyperSet`, whether via `msg.sender` or the recovered signer)
- one DKG vote per keyper
- votes are counted by `keccak256(abi.encode(pkElection, committeePKs))`
- different DKG results can receive votes independently
- finalization once one DKG result reaches the keyper threshold
- storage of the finalized election public key
- storage of finalized committee public keys
- `DKGVoteRegistered` includes the voting keyper and submitted `pkElection`
- `DKGResultPublished` includes the finalized `pkElection` and committee public keys

Ordering requirement:

- every keyper must submit `committeePKs` sorted by the immutable keyper indices from the election's `KeyperSet`
- `committeePKs[i]` must be the public key for `keyperSet.getMember(i)`
- a keyper can read its own index with `keyperSet.getMemberIndex(keyperAddress)`
- `committeePKs` ordering is part of the DKG result digest, so mismatched ordering votes for a different result

Read helpers:

- `isDKGFinalized`
- `getElection`

Validation:

- election public key must be 96-byte compressed G2 bytes
- each committee public key must be 96-byte compressed G2 bytes
- committee public key count must match keyper count

#### Ballot submission

Implemented behavior:

- public `submitVote(Ballot)`
- self-submit fee enforcement
- fee waiver for callers with `VOTE_PROXY_ROLE`
- append-only ballot storage
- on-chain storage of:
  - pseudonym
  - voter verification key
  - timestamp
  - submitting address
  - ciphertexts
  - ballot proof bytes
  - voter signature
  - WR attestation

Read helpers:

- `getNumBallots`
- `getBallot(bytes32 pseudonym)`
- `getBallots`
- `getElection`
- `getPhase`

Validation:

- DKG must be finalized
- voting must be within the configured time window
- pseudonym must be non-zero
- voter verification key must be a 48-byte compressed G1 point
- ciphertext count must equal `numCandidates`
- proof bytes must be present
- voter signature bytes must be present
- WR attestation bytes must be present
- each ciphertext point must be 96-byte compressed G2 bytes
- `msg.value` must match the expected fee rule exactly

#### Decryption share submission

Implemented behavior:

- `submitDecryptionShare(bytes[] shares, DLEQProof[] proofs)` — authorized by `msg.sender`
- `submitDecryptionShareSigned(bytes[] shares, DLEQProof[] proofs, bytes keyperSig)` — **meta-tx** variant (`ECDSA.recover`s the keyper), same relayer/gas model as DKG
- one share bundle per keyper
- on-chain storage of one share per candidate
- on-chain storage of one proof per candidate
- storage of the publishing keyper index

Read helpers:

- `getDecryptionShares`

Validation:

- DKG must be finalized
- voting must already be closed
- caller must be a keyper
- caller may only submit once
- `shares.length` must equal `numCandidates`
- `proofs.length` must equal `numCandidates`
- each share must be a 96-byte compressed G2 point

#### Aggregate publication

Implemented behavior:

- `publishAggregate(EncryptedTally)`
- restricted to `TALLY_AGGREGATOR_ROLE`
- aggregate ciphertext storage
- aggregate proof blob storage

Read helpers:

- `getAggregate`

Validation:

- DKG must be finalized
- voting must already be closed
- aggregate ciphertext count must equal `numCandidates`
- each aggregate ciphertext point must be 96-byte compressed G2 bytes

#### Final result publication

Implemented behavior:

- `publishResult(uint256[] totals, uint8[] keyperIndices)`
- restricted to `TALLY_AGGREGATOR_ROLE`
- storage of final totals
- storage of the keyper indices used for the tally
- later publications overwrite the stored result

Read helpers:

- `isResultFinalized`
- `getResult`

Validation:

- DKG must be finalized
- voting must already be closed
- totals length must match `numCandidates`
- `keyperIndices` must be non-empty

#### Admin: cancellation + fee withdrawal

Implemented behavior:

- `cancelElection()` — `DEFAULT_ADMIN_ROLE` only, strictly before `votingStart`; emits `ElectionCancelled`
- `withdrawFees(address payable recipient)`
- restricted to `DEFAULT_ADMIN_ROLE`
- `FeesWithdrawn` event emission
- direct ETH transfers rejected through `receive` and `fallback`

Validation:

- recipient must be non-zero
- failed ETH transfer reverts

## Shared Types

`src/VotingTypes.sol` defines the shared structs used across contract boundaries:

- `ElectionParams`
- `DLEQProof`
- `Ciphertext`
- `Ballot`
- `BallotRecord`
- `DKGResult`
- `ElectionConfigView`
- `EncryptedTally`
- `DecryptionShare`
- `ElectionResult`

All curve-related values are stored as raw `bytes` in contract storage.

## Stable Interfaces

The integration surface is exposed through:

- `IKeyperSet`
- `IElection`
- `IElectionRegistry`

These interfaces include:

- events
- external getters
- query helpers

## Finalized Design Decisions

The following decisions are already encoded in the contract implementation:

- duplicate keypers are not allowed
- elections can only be created from non-empty keyper sets with a valid threshold
- DKG publication uses threshold voting by full result digest, so the first keyper cannot pin the canonical result
- DKG committee public keys must be sorted by keyper index; use `KeyperSet.getMemberIndex(address)` to map a keyper address to its index
- ballot proof blobs, voter signatures, and WR attestations are stored on-chain
- WR public key is part of election configuration
- curve points are stored as `bytes`
- `submitVote` is public
- the fee waiver applies to the contract fee, not gas costs
- revotes are appended as new ballots
- one decryption-share bundle is stored per keyper, with one share and one proof per candidate
- fees are withdrawable only after election completion
- no on-chain pairing verification is performed

## Deployment Scripts

### `script/Deploy.s.sol`

`Deploy.s.sol` is the generic deployment script for any Foundry-supported network.

It:

- deploys `KeyperSet`
- deploys `ElectionRegistry`
- logs deployed addresses after broadcast

It does **not** publish an election. Use `script/PublishElection.s.sol` to create elections on top of an existing deployment.

Supported environment variables:

- `VOTE_MANAGER`
- `PRIVATE_KEY` fallback for deriving `VOTE_MANAGER` if `VOTE_MANAGER` is unset
- `KEYPERS` as a comma-separated list of keyper addresses
- or `KEYPER_COUNT` plus `KEYPER_1`, `KEYPER_2`, ... `KEYPER_N`
- `KEYPER_THRESHOLD`

If `KEYPER_THRESHOLD` is unset, it defaults to the full keyper count.

Example:

```shell
export PRIVATE_KEY=...
export KEYPERS=0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222,0x3333333333333333333333333333333333333333
export KEYPER_THRESHOLD=2

forge script script/Deploy.s.sol:DeployScript --rpc-url <RPC_URL> --broadcast
```

### `script/PublishElection.s.sol`

`PublishElection.s.sol` publishes (deploys) a new `Election` via an **existing**
`ElectionRegistry` and **existing** `KeyperSet`.

It calls:

- `ElectionRegistry.publishElection(IKeyperSet keyperSet, VotingTypes.ElectionParams params)`

Required environment variables (suitable for a `.env` file):

- `PRIVATE_KEY`: admin private key (must have `DEFAULT_ADMIN_ROLE` on the registry)
- `REGISTRY`: deployed `ElectionRegistry` address
- `KEYPER_SET`: deployed `KeyperSet` address
- `VOTING_START`: unix timestamp (seconds)
- `VOTING_END`: unix timestamp (seconds)
- `SELF_SUBMIT_FEE`: fee in wei for direct `submitVote` (set `0` if unused)
- `NUM_CANDIDATES`: number of candidates
- `BUDGET`: max selections / per-ballot budget parameter
- `PK_WR`: WR public key bytes (typically **48 bytes**, e.g. `0x...`)
- `TALLY_AGGREGATOR`: address that will hold `TALLY_AGGREGATOR_ROLE`
- `VOTE_PROXY`: address that will hold `VOTE_PROXY_ROLE`

Example `.env`:

```shell
PRIVATE_KEY=0x...
REGISTRY=0x...
KEYPER_SET=0x...

VOTING_START=1715000000
VOTING_END=1715003600
SELF_SUBMIT_FEE=0
NUM_CANDIDATES=2
BUDGET=1
PK_WR=0x...
TALLY_AGGREGATOR=0x...
VOTE_PROXY=0x...
```

Run:

```shell
set -a
source .env
set +a

forge script script/PublishElection.s.sol:PublishElection --rpc-url <RPC_URL> --broadcast
```

### `script/DeployAndPublishLocal.s.sol`

`DeployAndPublishLocal.s.sol` is a small local/demo bootstrap helper.

It deploys and publishes in one run:

- `KeyperSet` with 2 keypers (`KEYPER_1`, `KEYPER_2`) and threshold 2
- `ElectionRegistry`
- an initial `Election` via `ElectionRegistry.publishElection` (with quick defaults)

This script is meant for local demo flows only. For real deployments, use:

- `script/Deploy.s.sol` (deploy once)
- `script/PublishElection.s.sol` (publish elections many times)

## Validation

The contract package is covered by unit tests and invariant tests.

Test coverage includes:

- scaffold deployment
- keyper set construction and validation
- registry creation and validation rules
- DKG threshold voting
- ballot submission and reads
- decryption share submission and reads
- result finalization
- fee withdrawal
- stateful invariants for ballot count, share count, and fee balance

Validated commands:

```shell
forge build
forge test
```

At the time of writing, the full suite passes.

## Notes

- `getPhase()` currently returns `0`, `2`, `3`, and `4` (never `1` or `5`): `0` DKG phase, `2` DKG finalized / pre-voting, `3` voting open, `4` voting closed. There is no separate on-chain phase `1` (no distinct registration boundary), and result-finalization is read via `isResultFinalized()`, not a phase-5 return.
- `forge build` uses `via_ir = true` in `foundry.toml` because `getElection()` returns nested structs and otherwise hits Solidity stack-depth limits.

## Quick Commands

```shell
forge build
forge test
forge fmt
forge script script/Deploy.s.sol:DeployScript --rpc-url <RPC_URL> --broadcast
```
