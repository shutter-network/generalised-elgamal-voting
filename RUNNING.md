# Running geg — deployment guide

`geg` is one protocol over interchangeable data-layer backends; a deployment **picks a
backend** and every service is unchanged. Three compose stacks:

| Backend | Compose file | Status |
|---|---|---|
| **Database** (Postgres) | `deploy/docker-compose.db.yml` | Validated end-to-end (register → DKG → vote → tally) |
| **Blockchain** (Anvil devnet) | `deploy/docker-compose.chain-devnet.yml` | Validated: `tests/test_services_chain_daemon_e2e.py` runs this exact topology (coordinator relay + keyper HTTP servers writing to it + read-only data-layer service + coordinator DKG-over-HTTP + chain-direct admin + API ballot ingest) over Anvil to a correct on-chain tally; also driven by hand through a full election |
| **Blockchain** (real chain) | `deploy/docker-compose.chain.yml` | Same topology, external RPC + pre-deployed registry, no devnet tools. Config-only difference from the devnet stack |

**Attaching to an external data layer.** Those three stacks each run their own data
layer. When the data layer belongs to someone else — another system storing the
artifacts and serving the port contract over HTTP — run
`deploy/docker-compose.coordinator.yml` instead: the coordinator alone, pointed at that
URL with `GEG_DATA_LAYER_URL`, with no postgres, data-layer, api or admin service. The
keypers are unchanged (`deploy/docker-compose.keyper.yml`); they read the external data
layer's `/port` mount via `GEG_API_URL` and relay their writes through the coordinator
exactly as they do on the bundled stacks. Nothing in the code is aware of the
difference: `GEG_DATA_LAYER=database` has always meant "speak the port contract over
HTTP", and this only packages that configuration.

The automated test suite (`pytest`) is the integration test across all three
backends — in-memory, Postgres-over-HTTP, and blockchain-over-Anvil — including
the multi-operator HTTP keyper path. These composes are for **operating** the
system, not for testing correctness.

---

## Architecture

```
  ADMIN / OPERATOR STACK                              KEYPER STACKS (one per operator)
  admin / api (ballot ingest) ─▶ data-layer ─▶ DB|Chain      keyper 1
                                     ▲ reads                  keyper 2   ◀─ driven over HTTP by
  coordinator ────────────────────┘ writes (relays)  ◀──────▶ keyper 3      the coordinator
  (sole keyper bootstrapper; drives DKG + tally;             (hold only their own key)
   publishes the result)
```

- **Keypers run as separate stacks** (`docker-compose.keyper.yml`), one per operator — no
  shared Docker network. The coordinator reaches each by the URL in the election config
  (public, or `host.docker.internal` locally).
- **Database backend** — every component speaks HTTP to the one data-layer service, which
  verifies the caller's signature and writes to Postgres. Keypers POST signed writes to the
  coordinator, which relays them.
- **Blockchain backend** — authorization is by tx sender: admin (`ADMIN_SIGNING_KEY`) and
  the API ballot ingest (`GATEWAY_SIGNING_KEY`) submit their own txs. Keypers hold no chain
  key — they content-sign writes; the coordinator (`COORDINATOR_SIGNING_KEY`) pays gas, sends
  the `...Signed` tx (contract `ecrecover`s the keyper) and `publishResult` (it holds
  `RESULT_PUBLISHER_ROLE`). The data-layer service is read-only.

Identities are secp256k1 keys for write authorization (admin/gateway/coordinator/keyper).
Voter ballot + attestation keys are separate — Schnorr-G1, client-side.

---

# End-to-end walkthrough

Follow the steps in order — later steps depend on earlier services being up. Frontend steps
(5, 6, 8) are browser interactions; everything else is copy-paste.

## 0. Generate identities and envs

```bash
python scripts/gen_deploy_env.py
# writes deploy/.env + .env.eligibility + .env.keyper{1,2,3}
```

Writes (all git-ignored, split by concern): `deploy/.env` (operator stack),
`deploy/.env.eligibility` (issuer key + config), and `deploy/.env.keyper{1,2,3}` (each
keyper). See the matching `deploy/*.example` files.

This is a **local-dev generator**: operator EOAs are the pre-funded Anvil accounts [0..2]
(already hold ETH on the devnet; harmless on db). These keys are public — a real deploy
supplies its own funded keys and never uses this env against a real chain.

## 1. Start the three keypers

Keypers must be up **before** an election is registered, so the coordinator can reach them
for the DKG. Each runs as its own compose project (separate network, mirroring real
machines):

```bash
for n in 1 2 3; do
  docker compose -p keyper$n -f deploy/docker-compose.keyper.yml --env-file deploy/.env.keyper$n up -d --build
done
```

Confirm all three are reachable — each `/status` returns that keyper's `address` (its 20-byte
EOA, the value the register form resolves in step 5):

```bash
for p in 8101 8102 8103; do echo -n "keyper :$p → "; curl -s http://localhost:$p/status || echo unreachable; echo; done
```

Real operator (own machine): fill your own env, run one
```bash
cp deploy/.env.keyper.example deploy/.env.keyper
docker compose -f deploy/docker-compose.keyper.yml --env-file deploy/.env.keyper up -d --build
```
> Onboarding is one-time: give the admin your keyper's **public URL** (→ `config.keypers[].url`)
> and receive `COORDINATOR_IDENTITY` out of band; tokens are installed automatically over the
> signed `/auth/bootstrap` channel.

## 2. Start a stack (database or blockchain)

Pick one. Both bring up: data-layer, coordinator, api (reads + ballot ingest), admin.

```bash
# Database (Postgres):
docker compose -f deploy/docker-compose.db.yml --env-file deploy/.env up --build -d

# Blockchain (Anvil devnet) — compile contracts first; the registry is AUTO-DEPLOYED on `up`
# (deterministic address the services default to — no separate step, no pasting an address):
(cd contracts && forge build)
docker compose -f deploy/docker-compose.chain-devnet.yml --env-file deploy/.env up --build -d
```

> **Real chain** — identical to the devnet stack, but with `deploy/docker-compose.chain.yml`
> (no `anvil`, no auto `deploy-registry`, 12s polls). 
> **Prerequisite, one-time out of band:**
> deploy the `ElectionRegistry` once (`scripts/deploy_registry.py`) and set
> `GEG_REGISTRY_ADDRESS`, fund admin/gateway/coordinator with real ETH, and set
> `GEG_CHAIN_RPC` — all in `deploy/.env`. Then
> `docker compose -f deploy/docker-compose.chain.yml --env-file deploy/.env up -d --build`.

## 3. Start the eligibility service (+ whitelist)

The issuer runs standalone with its **own** env file. The bundled service is a **dummy** that
grants everyone by default.

**To whitelist specific addresses** (deny everyone else): edit
`deploy/eligibility-allowlist.json` — a `{address: weight}` map (Anvil [3..6] are pre-filled
as examples) — then set `ELIGIBILITY_ALLOWLIST=/app/eligibility-allowlist.json` in
`deploy/.env.eligibility` and start the service:

```bash
docker compose -f deploy/docker-compose.eligibility.yml --env-file deploy/.env.eligibility up --build -d
```

The file is re-read **per `/attest` request**, so you can add/remove wallets live (no
restart). An unlisted wallet gets `403` and no ballot is built. Unset the var → allow-all.

## 4. Start both frontends

```bash
npm --prefix frontend install                        # once
cp frontend/apps/admin/.env.example frontend/apps/admin/.env    # once (edit if ports differ)
cp frontend/apps/voter/.env.example frontend/apps/voter/.env    # once
npm --prefix frontend run dev:admin                  # http://localhost:5173
npm --prefix frontend run dev:voter                  # http://localhost:5174
```

Both apps are backend-blind (they read the public API on `:8500`). The admin app also talks
to the admin service (`:8300`) and the eligibility issuer (`:8600`).

## 5. Register the election (admin app)

In the admin app (`:5173`): connect the **admin wallet** (MetaMask — its account is the admin
EOA), fill the guided form, and register. Each action is authorized by a wallet signature (no
token); the form verifies the entered eligibility public key against the running issuer's
`/health` before signing. On chain, the service fires the register tx as the admin EOA
(`msg.sender == adminAddr`). Fill the election config and choose a suitable voting window.

**Form values for this local walkthrough** — all fixed public dev values from
`gen_deploy_env.py` (it also prints them):

- **Threshold** — `t = 1`, `n = 3` (1-of-3 → a quorum of 2 decrypts).
- **Keypers** — add three, one URL per line (the form resolves each address from its
  `/status`):
  ```
  http://host.docker.internal:8101
  http://host.docker.internal:8102
  http://host.docker.internal:8103
  ```
- **Eligibility signer** — a BLS public key (not an EOA), paste in full (fixed dev value;
  also in `deploy/.env.eligibility` or `curl -s http://127.0.0.1:8600/health`):
  ```
  0xa854a5ed41899e4927f256fea44a44c95d1a1a611989d1345d3fb7a971f51d2b1922694d9e66a31c1c82594763db9baf
  ```
- **Result-publisher address** — the coordinator (it publishes the result):
  `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` (Anvil [2]).
- **Blockchain stack only:**
  - **Vote-proxy address** — the gateway (the API's on-chain ballot sender):
    `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` (Anvil [1]).
  - **Self-submit fee** — the per-election fee for a voter self-paying their own `submitVote`
    (ETH); use `0` for fee-free. These two fields are hidden on the database stack.

Watch the DKG run in the logs (use your stack's compose file):

```bash
docker compose -f deploy/docker-compose.db.yml --env-file deploy/.env logs -f coordinator
docker compose -p keyper1 -f deploy/docker-compose.keyper.yml --env-file deploy/.env.keyper1 logs -f
```

Within a few seconds the finalized election key is readable (`00..01` = first election):

```bash
curl -s http://127.0.0.1:8500/elections/1/dkg/finalized
```

OR you can see it on the dashboard.

## 6. Cast votes (voter app)

Once the election is `Voting` (i.e. past `voting_start`) with a finalized key, open the voter
app (`:5174`), connect a **whitelisted** wallet (from step 3), pick the election, enter the
vote vector, and cast. The app fetches a credential from the eligibility service (`/attest`)
and submits the ballot to the public API — the ballot is built entirely in the browser. A
voter may re-cast until the window closes (last vote wins; see replay note below).

## 7. Wait for voting end → aggregate & decrypt

After `voting_end` the coordinator drives the tally automatically: it triggers the keypers to
aggregate (t+1 quorum → canonical), then to decrypt, recovers the result, and publishes it.
Watch it happen:

```bash
docker compose -f deploy/docker-compose.db.yml --env-file deploy/.env logs -f coordinator
docker compose -p keyper1 -f deploy/docker-compose.keyper.yml --env-file deploy/.env.keyper1 logs -f
```

## 8. Verify the final tally

Open the dashboard in either frontend — it shows the published totals per candidate. To
confirm from the API directly (totals reflect the ballots cast, each scaled by its
eligibility-attested weight):

```bash
curl -s http://127.0.0.1:8500/elections/1/result
#   → {"result":{"totals":[...],"keyperIndices":[1,2],"bsgsBound":...,...}}
```

## Teardown

```bash
docker compose -f deploy/docker-compose.db.yml --env-file deploy/.env down -v # or chain-devnet.yml
docker compose -f deploy/docker-compose.eligibility.yml --env-file deploy/.env.eligibility down -v
for n in 1 2 3; do docker compose -p keyper$n -f deploy/docker-compose.keyper.yml --env-file deploy/.env.keyper$n down; done
rm -rf postgres-data keyper-state* coordinator-state eligibility-state   # bind-mounted state at repo root
# postgres-data is db-stack only and holds the elections DB.
```

---

# Reference

### Ports
| Service | Port |
|---|---|
| data-layer | 8000 — **internal only**, not published to the host |
| keypers | separate stacks (local: 8101–8103) |
| admin | 8300 |
| coordinator | 8400 |
| public API (reads + ballot ingest) | 8500 — also serves the port read surface at `/port` |
| eligibility (standalone) | 8600 |
| admin app (dev) / voter app (dev) | 5173 / 5174 |

**Two read shapes on :8500 — which to curl.** The browser routes (`/elections/1/…`) take
the friendly decimal id and are what the frontends use, so they are the ones to reach for
when eyeballing an election by hand (the curls above). They are *display-shaped*: election
ids are decimalized and ballot pages cap at 200. The `/port` routes
(`/port/elections/<64-hex>/…`) are the byte-verbatim `ElectionDataLayer` contract —
bare-hex ids, ballot storage metadata, no cap. Use `/port` when the bytes matter
(re-deriving a digest, verifying a signature, reading every ballot) and when writing a
client that speaks the port; that is what keypers point `GEG_API_URL` at.

### Operational notes

**Re-votes & replay protection.** The eligibility service stamps each credential with a
monotonic per-(election, pseudonym) **nonce**, persisted in `ELIGIBILITY_NONCE_DB` (on the
`eligibility-state` bind mount). Two defenses use it: (1) the **tally** keeps only the
highest-nonce ballot per voter — authoritative and bypass-proof; (2) the **API ingest**
rejects a nonce `≤` the highest stored (`400 STALE_OR_REPLAYED`) — a best-effort funds/DoS
filter. The nonce is inside the signed attestation, so it can't be forged.

**Eligibility = sole authority on voter weight.** It binds each voter's weight into the signed
`ATTESTATION_V1` (over `electionId, pseudonym, vk, weight, nonce`); the config only sets policy
(`weighted`, `maxWeight` ceiling), and admission rejects `weight < 1` or `> maxWeight`. The
bundled stub grants a fixed `ELIGIBILITY_DUMMY_WEIGHT` (default 1); real weights come from the
integrator's source (token balance, registry, membership tier, …).

> **Production edge layer (required).** The bundled issuer is a dev stub on plain HTTP, called
> directly by voters' browsers. A real deployment MUST sit behind **TLS + a real DNS name** and
> a **reverse proxy (Caddy / nginx)** enforcing rate-limiting, request-size limits, and abuse
> protection on the unauthenticated `/attest`. `docker-compose.eligibility.yml` runs only the
> bare stub — add this layer yourself.

**Ballot gas & privacy (chain).** `submitVote` is `msg.sender`: **sponsor** (funded
`GATEWAY_SIGNING_KEY` on the ballot ingest) or **voters self-pay**. `selfSubmitFee` (per-election,
in the signed config) + `VOTE_PROXY_ROLE` tune the protocol fee; `selfSubmitFee = 0` is fee-free.
With the address-derived pseudonym (`keccak256(address ‖ electionId)`), self-pay puts the
address on-chain and deanonymizes the ballot — **sponsored submission keeps it off-chain** and
is the anonymity-preserving choice.

**Budget is bounded on the chain backend.** `submitVote` stores the whole ballot, and Variant A's
proof grows as `ℓ x (budget + 1)`, so at `ℓ = 3` a budget-100 ballot is ~78 KB — about **49M gas**
of storage against a 30M block limit. Casting fails with
`Out of gas: gas required exceeds allowance: 30000000`, which names the gas and not the cause.
Budget **10 or below** is fine at `ℓ = 3`; budget 100 is a **database-only** configuration for now.

**Timing.** You choose the voting window **in the register form** (step 5) — for a quick demo
pick a short one (e.g. a couple of minutes out and a couple of minutes long), leaving enough
lead time for the DKG.

**DKG integrity & complaints.** Keyper→keyper DKG traffic is signed (dealers sign their
commitments and shares, verified against the config member address) and each secret share is
**sealed** to the recipient's X25519 key, so nothing secret is on the wire. If a keyper's
Feldman-VSS check rejects a dealer's share it returns a **signed accusation**, and the
coordinator **halts the ceremony before publishing** rather than finalizing a divergent
transcript — the election then derives to `DKGFailed`, with the signed accusations in the
coordinator log for manual resolution (`op=dkg_complaint`). The accused dealer's
`/dkg/reveal_share` will disclose a share only to its own recipient (accusation-gated).

**Tally ordering & bounds.** The tally runs in strict order and only after `voting_end`, enforced at
every layer: the coordinator drives it only in the `Tallying` state, keypers self-guard, and the data
layer **and** chain contract **reject** an aggregate submitted before `voting_end`, and a decryption
share submitted before `voting_end` **or before a canonical aggregate exists**. The sequence is
aggregate → gate on the `t+1` canonical (byte-identical) quorum → **then** decrypt → publish. Each
phase is bounded by 5 coordinator polls; a tally that never reaches quorum (too many keypers down) is
**abandoned** — logged as `op=tally status=abandoned` **and** surfaced on the dashboard as a red
**`TallyStalled`** badge (a persisted flag; the coordinator is the only writer of "stalled"). It's
recoverable but **not** self-healing: the persisted flag is authoritative, so a **coordinator
restart does NOT resume a stalled tally**. The only way out is the **Retry** button on the admin
panel — the admin wallet signs a `clearTallyStalled`, which the admin service relays; the
coordinator then resumes with a **fresh 5-attempt budget** (bring the keypers back online first,
or it just re-stalls). A published result always supersedes it (→ `Complete`). Integrity is
independent of ordering — a bogus aggregate can't reach the quorum, and decryption shares are
DLEQ-verified against the canonical aggregate.

**Admin auth.** Each register/cancel is authorized by the admin wallet's signature (no token);
the same EOA is the wallet, `config.admin_key`, and `ADMIN_SIGNING_KEY`. "Changing keypers" is
per new election — each config names its own committee; URLs travel in the config (on chain the
`KeyperSet` stores them), read through the port — no URL env var.

**Rebuild after code changes:** re-run `up` with `--build`.

**Backend selection** via `GEG_DATA_LAYER`: `memory` (zero-dep local) · `database`
(`GEG_DATA_LAYER_URL` for clients / `GEG_DATA_LAYER_DSN` for the service) · `blockchain`
(`GEG_CHAIN_RPC`, `GEG_REGISTRY_ADDRESS`, each actor's own key).
