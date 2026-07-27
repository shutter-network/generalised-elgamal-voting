# Generalised Threshold ElGamal Voting (`geg`)

Storage-agnostic, privacy-preserving voting on linearly homomorphic **threshold
ElGamal** over BLS12-381. `geg` generalises two working systems — the Munich
Personalratswahl (staff-council election) and Snapshot X private voting — so that
the **storage backend** and the **identity source** become interchangeable
adapters behind ports, with **no change** to the voting protocol, the wire
format, or the audit procedure.

The same services run an entire election unchanged over three data-layer
backends: an in-memory reference, a Postgres microservice, and a blockchain
(BLS12-381 bulletin-board contracts on any EVM chain). Swapping backends is a
configuration change, not a code change.

- **Run it** (docker-compose, both backends): [`RUNNING.md`](./RUNNING.md)
- **Smart contracts:** [`contracts/README.md`](./contracts/README.md)

---

## What it does

- **Private ballots.** Votes are exponential-ElGamal ciphertexts under an election
  public key; individual votes are never decrypted — only the homomorphic
  aggregate is.
- **Threshold decryption.** A `(t+1)`-of-`n` keyper committee is generated per
  election by a distributed key generation (DKG) ceremony; no single party ever
  holds the decryption key. Any `t+1` keypers can jointly decrypt the tally; up to
  `t` compromised keypers learn nothing.
- **Weighted voting.** Each voter carries an attested weight; the tally is the
  weighted homomorphic sum `Σ wᵢ·ctᵢ` per candidate. Weight 1 is the degenerate
  one-person-one-vote case.
- **Publicly auditable.** Every stored artifact is self-verifying (zero-knowledge
  proofs + signatures). From public reads alone, anyone can recompute the DKG
  finalization, re-derive the admitted ballot set, re-verify every decryption
  share, re-run the recovery, and compare against the published result. Any
  mismatch is publishable evidence.
- **Backend-agnostic.** In-memory, Postgres, and blockchain adapters all satisfy a
  single `ElectionDataLayer` port and pass one shared conformance suite.

---

## How an election runs

```
Register ──▶ DKG ──▶ Vote ──▶ Tally ──▶ Decrypt ──▶ Result
```

1. **Register.** The admin publishes an immutable election config (candidates,
   voting window, `(t, n)` committee with keyper identities + endpoints, weighting
   rules). The registry assigns a sequential election id.
2. **DKG.** The coordinator drives a 2-round Feldman VSS ceremony across the keyper
   committee over authenticated HTTP, with **confidential round-2 shares travelling
   directly keyper→keyper** (no single process ever sees all shares). Only the
   public result — the election public key + per-member committee keys — reaches
   the data layer. A finalized key exists iff `≥ t+1` keypers submit a
   byte-identical result.
3. **Vote.** Voters build ballots in-browser (plaintext and proof randomness never
   leave the client) and submit them through the ballot gateway during the
   half-open window `[votingStart, votingEnd)`.
4. **Tally.** After `votingEnd`, the tally aggregator runs deterministic **ballot
   admission** (producing an admitted set + typed exclusion reasons), computes the
   weighted homomorphic aggregate, and publishes it.
5. **Decrypt.** The aggregator triggers the keypers; each keyper re-checks the
   decryption preconditions against the data layer, produces its partial decryption
   share with a DLEQ proof, and submits it.
6. **Result.** Given `t+1` verified shares, the aggregator Lagrange-combines them
   and recovers the per-candidate totals by baby-step/giant-step within a bound
   derived from the admitted weights, then publishes the result. The election
   becomes immutable.

**Derived state, never stored.** No service owns a mutable state machine. Every
service and auditor re-derives the lifecycle state
(`Registered → KeyReady → Voting → Tallying → Complete`, plus `Cancelled`,
`DKGFailed`, `Void`) from `(data-layer facts, now)`. Keypers **never trust a
trigger** — they re-verify preconditions themselves.

---

## Architecture

Three planes talk to storage **exclusively** through the `ElectionDataLayer`
port — never a chain or DB directly:

- **Admin plane** — Election Admin (sole config writer), DKG Coordinator daemon,
  Tally Aggregator daemon.
- **User plane** — Eligibility Service (issues the `ATTESTATION_V1` credential),
  Ballot Gateway (ingest + on-by-default filter), the browser crypto SDK.
- **Committee plane** — `n` Keyper services: fresh DKG per election, precondition-
  guarded partial decryption, private state encrypted at rest.

### Two abstraction seams

1. **`ElectionDataLayer` port** — the bulletin board. Adapters: **in-memory**
   (reference + executable spec), **database** (HTTP microservice over Postgres),
   **blockchain** (web3 over Foundry contracts). All three pass one conformance
   suite. The data layer is **trusted for availability only** — a malicious backend
   can censor or hide, but can never forge an accepted artifact or an undetected
   wrong result.
2. **`EligibilityService` port** — issues/verifies `ATTESTATION_V1` over
   `(electionId, pseudonym, vk, weight)`. Issuance is adapter-specific (stub,
   wallet/EIP-712, OIDC, Wahlregister); **verification is normative and pure**.

**Integrator responsibility.** Voter *eligibility* and *who pays ballot gas* on the
blockchain backend belong to the external service integrating `geg`, not to `geg`
itself. Eligibility is the port above; gas is config-only (on-chain `submitVote` is
authorized by `msg.sender`, so the integrator either sponsors submission with a
funded key or lets voters self-pay). Note the privacy coupling for address-derived
pseudonyms — self-pay puts the voter's address on-chain and can deanonymize the
ballot, so sponsored submission is the anonymity-preserving choice. See
[`RUNNING.md`](./RUNNING.md).

### Source layout (`src/geg/`)

Layered top-to-bottom so imports flow downward:

- **`core/`** — the pure protocol kernel (no I/O): `config`, `state` (state
  derivation), `admission` (the correctness kernel), `aggregation` (weighted sum +
  recovery), `authz`, `write_auth`.
- **`crypto/`** — the BLS12-381 suite (ElGamal-G2, Schnorr-G1, DLEQ/OR/budget
  proofs, Feldman DKG, Lagrange + BSGS recovery).
- **`envelopes/`** — JSON transport envelopes + byte codecs (the interop contract).
- **`ports/`** — the abstraction seams (`data_layer`, `eligibility`, `keyper_p2p`).
- **`adapters/`** — backends behind the ports (`memory`, `db/`, `chain/`, eligibility).
- **`services/`** — one domain package per actor, each exposing a `__main__` when
  deployable.

---

## Data-layer backends

| Backend | Adapter | Authorization | Notes |
|---|---|---|---|
| **In-memory** | `geg.adapters.memory` | request signatures | Reference + executable spec; the conformance suite's baseline |
| **Database** | `geg.adapters.db` | request signatures (verified server-side) | Flask microservice + `HttpDataLayerClient` over Postgres; jsonb envelopes, per-election stable ordering under a row lock |
| **Blockchain** | `geg.adapters.chain` + `contracts/` | transaction sender + meta-tx | web3 over the Foundry bulletin-board; one adapter instance per actor bound to that actor's key |

All three satisfy the same port and run the same services; only the deployment
config differs.

---

## Services

Every actor is a deployable service (`python -m geg.services.<name>`):

| Service | Package | Role |
|---|---|---|
| **Data layer** | `data_layer` | Uniform HTTP service fronting any backend via `GEG_DATA_LAYER=memory\|database\|blockchain` |
| **Public read API** | `api` | Read-only, CORS-enabled HTTP surface for frontends / external callers (port 8500); backend-blind — reads through the data-layer service |
| **Keyper** (×n) | `keyper` | Holds its identity + encrypted private state; runs DKG over HTTP; precondition-guarded `/decrypt` |
| **Coordinator** | `coordinator` | Auto-DKG watcher: drives the DKG ceremony; **relays** keyper DKG/decryption writes to the data layer |
| **Tally aggregator** | `tally_aggregator` | Polls for closed elections; admit → aggregate → trigger keypers → recover → publish result |
| **Gateway** | `gateway` | Ballot ingest + on-by-default (non-authoritative) filter |
| **Admin** | `admin` | `register`/`cancel` as CLI and admin-only HTTP service (bearer-gated) |
| **Auditor** | `auditor` | Independent re-verification of a finalized election from public reads |

---

## Security & authorization model

- **Write authorization is unified to secp256k1 / Ethereum `ecrecover`** across
  every actor (admin, aggregator, gateway, coordinator, keyper). On the in-memory
  and database backends this is an EIP-191 request signature verified by
  `geg.core.authz`; on chain it is the transaction sender.
- **Voter keys stay separate.** Ballot and attestation keys are Schnorr over G1
  (client-side), unrelated to the write-authz identities.
- **Keypers hold no data-layer write path and no gas.** They content-sign their DKG
  result and decryption shares and POST `{payload, signature}` to the
  **coordinator**, which relays them:
  - on the DB backend, the coordinator forwards the signed write to the data-layer
    service;
  - on chain (**Option A**), admin/aggregator/gateway submit their own transactions
    (`msg.sender`), and **only keyper writes are relayed** as meta-transactions —
    the coordinator's relayer pays gas and the contract `ecrecover`s the keyper as
    the true author. The relayer holds no on-chain role.
- **Keyper bootstrap trust set.** A keyper's HTTP API is fail-closed behind bearer
  tokens installed via an X25519-sealed, secp256k1-signed (EIP-191) `/auth/bootstrap`
  with a replay guard. A keyper pins a **set** of trusted bootstrapper identities —
  the **coordinator** (drives DKG) and the **tally aggregator** (triggers
  decryption) — so each drives the keyper signing with its own key, and neither
  needs to hold the other's. (Consolidating this into a single keyper orchestrator
  is a planned phase-2 change.)
- **Threshold guarantee is real.** DKG round-2 shares travel directly
  keyper→keyper; no single process observes all shares. Keyper secrets persist
  Fernet-encrypted at rest (key derived from the signing key), so a keyper survives
  the gap between DKG and decryption and reloads on restart.

---

## Cryptographic suite (protocol v1)

- **Group:** BLS12-381. ElGamal ciphertexts + DKG in **G2** (96-byte compressed);
  Schnorr signatures + attestations in **G1** (48-byte compressed). Zcash byte
  format, subgroup-checked on deserialize.
- **Encryption:** exponential ElGamal `C1 = r·P2`, `C2 = r·mpk + m·P2`; homomorphic
  by point addition.
- **Threshold:** `(t+1)`-of-`n` Feldman VSS DKG; partial decrypt `σ_k = msk_k·C1`
  with a DLEQ proof; Lagrange interpolation at zero; baby-step/giant-step recovery.
- **Proofs:** Fiat-Shamir over a Merlin-style transcript; **keccak256** throughout
  (fixed for cross-language vector compatibility).
- **Ballot validity:** Variant A (OR proof over `{0..B}`), mode **exact** (`Σ = B`),
  weighted. Variant B (bit decomposition) and mode **atMost** are specified and
  test-vectored but deferred in the reference implementation (conformance level 2).

**Byte-for-byte TS↔Python compatibility is a protocol requirement,** enforced by a
cross-language conformance-vector suite (not merely a CI convenience). The browser
crypto is the published npm package `@shutter-network/urban-verified-crypto`; the
Python side reimplements the same byte formats and verifies the same vectors.

---

## Smart contracts

The blockchain backend is a Foundry project under [`contracts/`](./contracts):

- `ElectionRegistry` — admin-gated factory + index; assigns sequential election ids.
- `KeyperSet` — immutable committee: members + per-member HTTP endpoints + threshold.
- `Election` — per-election state machine (DKG voting, ballots, decryption shares,
  aggregate, result), assembled from facet contracts.

All curve points are stored as raw `bytes`; there is **no on-chain pairing or proof
verification** — validation is the auditor's (off-chain) responsibility, which keeps
gas costs down and matches the availability-only trust model. Keyper writes support
meta-transaction variants (`voteDKGResultSigned`, `submitDecryptionShareSigned`) so
the relayer pays gas while the contract recovers the keyper as author. See
[`contracts/README.md`](./contracts/README.md) for the full interface.

---

## Layout

```
src/geg/
  core/                # pure protocol kernel: config, state, admission,
                       #   aggregation, authz, write_auth
  crypto/              # BLS12-381 crypto suite (ElGamal-G2, Schnorr-G1, proofs, DKG)
  envelopes/           # JSON transport envelopes + codecs
  ports/               # abstraction seams: data_layer, eligibility, keyper_p2p
  adapters/            # backends behind the ports: memory, db/, chain/, eligibility
  services/            # one domain package per actor: keyper/, coordinator/,
                       #   tally_aggregator/, gateway/, admin/, auditor/, data_layer/
contracts/             # Foundry bulletin-board contracts (blockchain backend)
deploy/                # docker-compose (db, chain-devnet, chain) — see RUNNING.md
scripts/               # env generation, sample voter, chain deploy helpers
tests/                 # unit, conformance, and end-to-end suites (+ vectors/)
```

---

## Install & test

Clone with submodules (the Foundry contract dependencies live in
`contracts/lib/` as pinned git submodules):

```sh
git clone --recurse-submodules <repo-url>
# already cloned without them? fetch with:
git submodule update --init
```

```sh
pip install -e '.[dev,db,chain]'
pytest
```

The Python test suite (**290 passing, 3 skipped**) is the integration test across
all three backends — in-memory, Postgres-over-HTTP, and blockchain-over-Anvil —
including the multi-operator HTTP keyper path. The Postgres tests use a dockerized
database (`docker compose up -d`) and the chain tests use Anvil (Foundry); both
skip cleanly if those aren't available.

The contracts have their own Foundry suite (**55 tests**):

```sh
cd contracts && forge test
```

---

## Running

See [`RUNNING.md`](./RUNNING.md) for the full deployment guide. Two docker-compose
stacks are provided — a Postgres stack (`docker-compose.db.yml`) and a blockchain
stack (`docker-compose.chain-devnet.yml` for a throwaway Anvil devnet,
`docker-compose.chain.yml` for a real chain). Both have been driven through a
complete election by hand (register → DKG → vote → tally → decrypt → result),
producing identical results — the same services, the same wire format, only the
data layer differs.

---

## Status & roadmap

**Implemented end-to-end.** All three data-layer backends satisfy one port; the
same services run a full election on each, validated by the automated suite and by
hand-driven multi-election runs on both the Postgres and chain stacks.

Deferred beyond v1: keyper-set rotation/discovery, phase-2 consolidation of keyper
orchestration, trust-minimizing the aggregate (keypers threshold-publish it), an
optional ballot meta-transaction, and admin auth model B.
