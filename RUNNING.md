# Running geg — deployment guide

How to actually run the system. `geg` is one protocol over interchangeable
data-layer backends; a deployment **picks a backend** and every service is
unchanged. Two docker-compose stacks are provided:

| Backend | Compose file | Status |
|---|---|---|
| **Database** (Postgres) | `deploy/docker-compose.db.yml` | Validated end-to-end (register → DKG → vote → tally) |
| **Blockchain** (Anvil devnet) | `deploy/docker-compose.chain-devnet.yml` | Validated: `tests/test_services_chain_daemon_e2e.py` runs this exact topology (coordinator relay + keyper HTTP servers writing to it + read-only data-layer service + coordinator DKG-over-HTTP + chain-direct admin/aggregator/gateway) over Anvil to a correct on-chain tally; also driven by hand through a full election |
| **Blockchain** (real chain) | `deploy/docker-compose.chain.yml` | Same topology, external RPC + pre-deployed registry, no devnet tools. Config-only difference from the devnet stack |

The automated test suite (`pytest`) is the integration test across all three
backends — in-memory, Postgres-over-HTTP, and blockchain-over-Anvil — including
the multi-operator HTTP keyper path. These composes are for **operating** the
system, not for testing correctness.

---

## The model in one picture

```
  ADMIN / OPERATOR STACK                              KEYPER STACKS (one per operator)
  admin / gateway / aggregator ─▶ data-layer ─▶ DB|Chain      keyper 1
                                     ▲ reads                  keyper 2   ◀─ driven over HTTP by
  coordinator ────────────────────┘ writes (relays)  ◀──────▶ keyper 3      the coordinator/aggregator
  (sole keyper bootstrapper; drives DKG)                     (hold only their own key)
```

**Keypers now run as separate stacks** (`docker-compose.keyper.yml`), one per
operator — they are independent entities. The admin/operator stack
(`docker-compose.{db,chain-devnet,chain}.yml`) holds everything else. The
coordinator and aggregator reach each keyper by the URL in the election config
(public, or `host.docker.internal` for local testing) — there is no shared Docker
network between the stacks. See **"Keypers (run separately)"** below.

* **Database backend** — every component speaks HTTP to the one data-layer
  service, which verifies the caller's signature and writes to Postgres. Keypers
  read from it but POST their signed writes to the **coordinator**, which relays
  them to the data-layer service.
* **Blockchain backend** — authorization is by transaction sender, so
  admin/aggregator/gateway hold their **own** keys and submit their own txs
  directly. **Keypers hold no chain key**: they content-sign their DKG and
  decryption writes and POST them to the **coordinator**, which runs the
  **relayer** account (`GEG_RELAYER_KEY`) that pays gas and sends the `...Signed`
  tx — the contract `ecrecover`s the keyper as the on-chain author (Option A). The
  relayer holds no on-chain role, so it never stands in for admin/aggregator/gateway.
  The data-layer service on chain is then **reads-only** (the public read surface).

Identities are secp256k1 (Ethereum) keys for **write authorization** on every
backend (admin/aggregator/gateway/coordinator/keyper). Voter **ballot** and
**attestation** keys are unrelated and remain Schnorr-G1 (client-side).

---

## 0. Generate identities (both backends)

The keyper keys must match the config's keyper `signing_key`s and the coordinator
key must match the address keypers pin — so generate them coherently:

```bash
python scripts/gen_deploy_env.py     # writes deploy/.env + deploy/sample-election.json
```

`deploy/.env` holds every private key (git-ignored — don't commit it);
`deploy/sample-election.json` is a valid §7.2 config envelope wired to the
generated keyper endpoints/addresses. See `deploy/.env.example` for the full
variable list. `gen_deploy_env.py` writes each keyper's endpoint as
`http://host.docker.internal:810N` (local split); set
`KEYPER_ENDPOINTS=url1,url2,url3` before running it for a real multi-machine deploy.

---

## Keypers (run separately)

Keypers are **independent operators**, each running `docker-compose.keyper.yml` on
their own machine — they hold only their own signing key. A keyper is
backend-agnostic: it just speaks HTTP to the admin's data-layer (reads) and
coordinator (write-relay), pins the coordinator's address, and is driven over HTTP.
Start the keypers **before** registering an election so the coordinator can reach
them for the DKG.

**Local testing (all three on one host).** `gen_deploy_env.py` writes a
self-contained env per keyper — `deploy/.env.keyper1/2/3` (each: its key, port
810N, state dir, and the shared coordinator id/token/URLs). Start each as its own
stack (distinct compose project → own network, mirroring separate machines):

```bash
for n in 1 2 3; do
  docker compose -p keyper$n -f deploy/docker-compose.keyper.yml --env-file deploy/.env.keyper$n up -d --build
done
```

**Real operator (own machine).** Fill in your own env and bring up one keyper:

```bash
cp deploy/.env.keyper.example deploy/.env.keyper     # your key + admin's coordinator id/token + public URLs
docker compose -f deploy/docker-compose.keyper.yml --env-file deploy/.env.keyper up -d --build
```

Onboarding is one-time and needs a single pre-shared value: share your keyper's
**public URL** with the admin (it goes into `config.keypers[].endpoint`) and receive
`COORDINATOR_IDENTITY` from them out of band. No tokens to mint or hold — the
coordinator installs both your inbound bearer token **and** your relay token over the
sealed, signed `/auth/bootstrap` channel once it can reach your `/status`.

---

## Database backend

```bash
# build + start the admin/operator stack: postgres, data-layer, coordinator,
# tally-aggregator, gateway, api. (Keypers are SEPARATE — start them first, per
# "Keypers (run separately)" above.)
docker compose -f deploy/docker-compose.db.yml --env-file deploy/.env up --build -d

# register the sample election (admin CLI, one-shot)
docker compose -f deploy/docker-compose.db.yml --env-file deploy/.env \
  run --rm admin register --config /config/sample-election.json

# the coordinator discovers it, bootstraps the keypers, runs the DKG;
# within a few seconds the finalized key is readable:
curl -s http://127.0.0.1:8000/elections/0000000000000000000000000000000000000000000000000000000000000001/dkg/finalized

# once inside the voting window, cast ballots via the gateway (reference voter):
GEG_DATA_LAYER_URL=http://127.0.0.1:8000 GATEWAY_URL=http://127.0.0.1:8200 \
  ELIGIBILITY_PRIVATE_KEY=$(grep '^ELIGIBILITY_PRIVATE_KEY=' deploy/.env | cut -d= -f2) \
  python scripts/vote_sample.py               # submits [3,0,0]w2 + [0,3,0]w5

# after voting_end the tally-aggregator daemon tallies; read the result:
curl -s http://127.0.0.1:8000/elections/0000000000000000000000000000000000000000000000000000000000000001/result
#   → {"result":{"totals":[6,15,0],"keyperIndices":[1,2],"bsgsBound":21,...}}
```

Voting window and tally deadline are set relative to generation time
(`voting_start` ≈ now + 5 min by default). For a quick demo use a short real-time
window: `VOTING_START_OFFSET=90 VOTING_DURATION=90 python scripts/gen_deploy_env.py`.
Voters submit ballots to the gateway (`http://127.0.0.1:8200`) during the window;
after `voting_end` the tally aggregator publishes the aggregate, triggers the
keypers, recovers the result, and publishes it. Read anything back through the
data-layer service on `:8000`. Timing here is plain wall-clock (the data-layer
service is the NTP-disciplined authority) — no Anvil-style block-time concern.

This stack has been driven through a **complete election by hand** (register → DKG
→ 2 weighted ballots → tally → `totals=[6,15,0]` with 3 shares on the data layer),
producing an identical result to the blockchain backend — same services, same wire
format, only the data layer differs.

Tear down the admin stack (DB + token-store), then the keyper stacks:

```bash
docker compose -f deploy/docker-compose.db.yml --env-file deploy/.env down -v
for n in 1 2 3; do docker compose -p keyper$n -f deploy/docker-compose.keyper.yml down; done
rm -rf deploy/keyper-state* token-store            # encrypted keyper state + shared tokens
```

### Ports
| Service | Port |
|---|---|
| data-layer | 8000 |
| keypers | separate stacks, host-published (local: 8101–8103) |
| gateway | 8200 |
| admin | 8300 |
| coordinator | 8400 |
| public read API | 8500 |

### Admin API (admin-only)

The admin service also runs as an HTTP endpoint (`serve`, port 8300), gated by a
fail-closed bearer token (`ADMIN_API_TOKEN`) — auth model **A** (the service holds
`ADMIN_SIGNING_KEY`; a frontend holds the token). Model B (frontend signs, server
relays) is a later-version TODO. Endpoints:

```bash
TOKEN=$(grep '^ADMIN_API_TOKEN=' deploy/.env | cut -d= -f2)

# register an election (the committee — keyper identities + URLs — is in the config)
curl -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d "{\"config\": $(cat deploy/sample-election.json)}" \
  http://127.0.0.1:8300/elections            # → {"electionId":"0x..01"}

# cancel before voting_start
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8300/elections/<eid-hex>/cancel
```

The equivalent CLI (`run --rm admin register --config …`) still works. "Changing
keypers" is per **new** election: each `POST /elections` names its own committee in
the config, so successive elections can use different or partly-replaced keyper sets
(k1,k2,k3 then k2,k3,k4). The keyper URLs travel in that config and are stored in the
data layer on **every** backend — including on chain, where the `KeyperSet` contract
holds each member's URL — so services read them through the port; there is no
endpoint env var.

---

## Blockchain backend (Anvil devnet)

Chain deploys need the Foundry artifacts and the (randomly generated) accounts
must be funded on the devnet, so bring-up is ordered:

```bash
# 0. compile contracts (produces contracts/out, mounted into the deploy tools)
(cd contracts && forge build)

# 1. identities + sample config (short real-time window for the demo)
VOTING_START_OFFSET=110 VOTING_DURATION=120 python scripts/gen_deploy_env.py

# 2. start the devnet
docker compose -f deploy/docker-compose.chain-devnet.yml --env-file deploy/.env up -d anvil

# 3. fund the generated accounts on the devnet
docker compose -f deploy/docker-compose.chain-devnet.yml --env-file deploy/.env run --rm fund

# 4. deploy the registry with the ADMIN key; copy the printed address into deploy/.env
docker compose -f deploy/docker-compose.chain-devnet.yml --env-file deploy/.env run --rm deploy-registry
#   → prints GEG_REGISTRY_ADDRESS=0x...   (paste it into deploy/.env)

# 5. start the admin stack (data-layer reads, coordinator=relayer, aggregator,
#    gateway, api), then the keyper stacks (separate — see "Keypers (run separately)").
docker compose -f deploy/docker-compose.chain-devnet.yml --env-file deploy/.env up -d
for n in 1 2 3; do
  docker compose -p keyper$n -f deploy/docker-compose.keyper.yml --env-file deploy/.env.keyper$n up -d --build
done

# 6. register the election on chain (admin submits its own tx → becomes adminAddr)
docker compose -f deploy/docker-compose.chain-devnet.yml --env-file deploy/.env \
  run --rm admin register --config /config/sample-election.json

# 7. auto-DKG finalizes the key within a few seconds (keyper writes relayed to chain):
curl -s http://127.0.0.1:8000/elections/0000000000000000000000000000000000000000000000000000000000000001/dkg/finalized

# 8. once inside the voting window, cast ballots via the gateway (reference voter):
GEG_DATA_LAYER_URL=http://127.0.0.1:8000 GATEWAY_URL=http://127.0.0.1:8200 \
  ELIGIBILITY_PRIVATE_KEY=$(grep '^ELIGIBILITY_PRIVATE_KEY=' deploy/.env | cut -d= -f2) \
  python scripts/vote_sample.py               # submits [3,0,0]w2 + [0,3,0]w5

# 9. after voting_end the tally-aggregator daemon publishes the aggregate, triggers
#    the keypers to decrypt (shares relayed), and finalizes — read the result:
curl -s http://127.0.0.1:8000/elections/0000000000000000000000000000000000000000000000000000000000000001/result
#   → {"result":{"totals":[6,15,0],"keyperIndices":[1,2],"bsgsBound":21,...}}
```

From here the flow mirrors the database backend: the coordinator drives the DKG
and **relays keyper writes** (gas paid by `GEG_RELAYER_KEY`, authorship = the keyper
via `ecrecover`); voters submit ballots via the gateway; the aggregator tallies. The
difference is purely where authz lives — tx sender vs. a verified request signature.

> **Devnet timing.** The chain compose runs Anvil with `--block-time 1` so
> `block.timestamp` advances with wall-clock. Without interval mining Anvil only
> stamps a block per transaction, so the chain's "now" freezes between txs and
> time-gated calls (voting window / tally) evaluate against a stale timestamp. For
> a quick demo set a short real-time window when generating identities, e.g.
> `VOTING_START_OFFSET=110 VOTING_DURATION=120 python scripts/gen_deploy_env.py`,
> and let real time pass (don't warp — services derive state from wall-clock, which
> on a real chain matches `block.timestamp`).

> **Keyper endpoints on chain.** The `KeyperSet` contract stores each member's URL
> alongside its address (set at registration), so the coordinator/aggregator read
> keyper endpoints straight from the election config via the data-layer port — same
> as the database backend. No endpoint env var.

This stack has been brought up by hand through a **complete election** — anvil →
fund → deploy-registry → register → auto-DKG finalizes on chain → two weighted
ballots via the gateway → tally-aggregator publishes the aggregate, triggers the
keypers (3 shares relayed to chain), and finalizes `totals=[6,15,0]` read back from
chain — in addition to the automated `test_services_chain_daemon_e2e.py` that runs
the same topology.

> **Note on maturity.** This exact topology is covered by an automated end-to-end,
> `tests/test_services_chain_daemon_e2e.py` (coordinator relay + keyper HTTP
> servers writing to it + read-only data-layer service + coordinator DKG-over-HTTP + chain-direct
> admin/aggregator/gateway → correct on-chain tally), alongside the adapter tests
> `tests/test_services_chain_e2e.py` / `tests/test_adapter_chain.py`. `register`
> lives on the size-constrained `ElectionRegistry`, so it stays a direct admin tx
> rather than a relayed meta-tx.

---

## Blockchain backend (real chain)

For a real network, use **`deploy/docker-compose.chain.yml`** — no node, no funding
cheat, no fresh registry. The `ElectionRegistry` is a long-lived contract deployed
**once per chain**, and accounts are funded with real ETH out of band. You provide
`GEG_CHAIN_RPC`, `GEG_REGISTRY_ADDRESS`, and the actor keys in `deploy/.env`.

```bash
# one time, out of band:
#   • deploy the registry once (scripts/deploy_registry.py against your RPC), and
#     put its address in deploy/.env as GEG_REGISTRY_ADDRESS
#   • fund admin / aggregator / gateway / relayer with real ETH
#   • set GEG_CHAIN_RPC in deploy/.env

docker compose -f deploy/docker-compose.chain.yml --env-file deploy/.env up -d --build
docker compose -f deploy/docker-compose.chain.yml --env-file deploy/.env \
  run --rm admin register --config /config/election.json
```

The election id is **assigned by the registry** (sequential); read it back from the
data-layer service (`GET /elections` → `electionIds`) — `scripts/vote_sample.py`
discovers it automatically (or set `GEG_ELECTION_ID`). Everything else matches the
devnet flow; the daemons poll cheaply via the dense `electionCount` + `getElections`
walk (no event scan), so a long-lived registry with many elections stays cheap.

Differences from the devnet compose: external RPC (no `anvil`), no `fund` /
`deploy-registry` tools, `restart: unless-stopped` on the long-running services,
and slower poll intervals (12s) suited to real block times. `GEG_CHAIN_RPC` and
`GEG_REGISTRY_ADDRESS` are required — compose errors if unset.

> **Eligibility and ballot gas are the integrator's responsibility, not geg's.**
> Eligibility is the `EligibilityService` port (the integrator supplies the issuance
> adapter). Ballot gas is not baked in: `submitVote` is `msg.sender`, so the
> integrator chooses by config — **sponsor** (run the submitter with a funded key;
> the gateway's `GATEWAY_SIGNING_KEY`, or the eligibility service itself) or
> **voters self-pay** (their wallet sends the tx). `selfSubmitFee` + `VOTE_PROXY_ROLE`
> tune the protocol fee (separate from gas); with `selfSubmitFee = 0` no role grant
> is needed.
>
> **Privacy coupling:** whoever sends the tx is `msg.sender` on-chain. With the
> wallet adapter's address-derived pseudonym (`keccak256(address ‖ electionId)`),
> voter self-pay puts the address on-chain and lets anyone recompute the link →
> deanonymizes the ballot; **sponsored submission keeps the address off-chain** and
> is the anonymity-preserving choice. Non-address-derived pseudonyms are unaffected.
> An optional `submitVoteSigned` meta-tx (voter signs, a relayer pays gas) would give
> pay-nothing *and* address-off-chain, but is an unbuilt v1 extension.

---

## Tip — rebuild the one-shot tools after code changes

`admin` / `fund` / `deploy-registry` are `profiles: ["tools"]`, so `up --build` does
**not** rebuild them (they aren't started by `up`). `docker compose run` builds a
tool image on first use and then caches it — so after changing code, run the tool
with `--build` (cheap; only the changed `COPY src` layer rebuilds):

```bash
docker compose -f deploy/docker-compose.db.yml --env-file deploy/.env \
  run --rm --build admin register --config /config/sample-election.json
```

## Backend selection reference

Set on each service via env:

* `GEG_DATA_LAYER = memory | database | blockchain`
* database: `GEG_DATA_LAYER_URL` (clients) / `GEG_DATA_LAYER_DSN` (the service)
* blockchain: `GEG_CHAIN_RPC`, `GEG_REGISTRY_ADDRESS`, each actor's own key, and
  `GEG_RELAYER_KEY` on the data-layer service

The uniform data-layer service (`python -m geg.services.data_layer`) also accepts
`GEG_DATA_LAYER=memory` for a zero-dependency local run.
