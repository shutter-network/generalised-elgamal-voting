# geg frontends

```
frontend/
  shared/            @geg/shared — typed API client, deriveState(), dashboard components (Vite-aliased)
  apps/admin/        register / cancel elections + dashboard
  apps/voter/        cast an encrypted ballot (client-side crypto) + dashboard
```

Both apps are **backend-blind**: the dashboard reads only the public API (`:8500`), which
serves identical JSON whether a database or blockchain data layer is behind it.

## Prerequisites

- Node 18+ and npm.
- A running geg stack with the **public API** (reads + ballot ingest, `:8500`), the
  **admin** service (`:8300`), and an **eligibility** issuer (`:8600`, run standalone via
  `deploy/docker-compose.eligibility.yml`) reachable (see the repo's `RUNNING.md`).

## Install

```sh
npm --prefix frontend install
```

## Configure

Each app reads service URLs from Vite env vars. Copy the examples and edit if your ports
differ from the localhost defaults:

```sh
cp frontend/apps/admin/.env.example frontend/apps/admin/.env
cp frontend/apps/voter/.env.example frontend/apps/voter/.env
```

`VITE_API_URL` (8500, reads + ballot ingest), `VITE_ADMIN_URL` (8300),
`VITE_ELIGIBILITY_URL` (8600).

## Voter app: blst wasm assets

The crypto SDK (`@shutter-network/urban-verified-crypto`) loads `blst.js` + `blst.wasm`
at `initCurves()`. These are **copied automatically** from the SDK into
`apps/voter/public/` by the voter app's `postinstall` (a plain `cp` in its
`package.json`) — so `npm install` sets them up; no manual step. (Re-run `npm install`
or `npm run postinstall -w @geg/voter` if they go missing.)

## Run (dev)

```sh
npm --prefix frontend run dev:admin     # http://localhost:5173
npm --prefix frontend run dev:voter     # http://localhost:5174
```

- **Admin**: connect the admin wallet (MetaMask, top-right) — its account is the admin
  EOA (`config.admin_key`). Then register (guided form, or paste a config JSON) / cancel;
  each action is authorized by a wallet signature (no token). The form is **data-store
  aware** (via the API's `/capability`): blockchain-only fields (on-chain vote-proxy
  sponsor + self-submit fee) appear only when the API is on the blockchain backend and are
  absent on a database election. Register also verifies the entered eligibility public key
  matches the running issuer (`/health`) before signing.
- **Voter**: pick an election; when it's `Voting` with a finalized key, enter the vote
  vector and cast — the ballot is built entirely in the browser.

## Checks

```sh
npm --prefix frontend test        # Vitest: deriveState() mirror
npm --prefix frontend run build   # production build of both apps
```

## Notes

- Admin auth is model **B**: the admin wallet (MetaMask) signs each register/cancel and
  the service relays the signature — no shared token. The connected account is the admin
  EOA (== `config.admin_key`; on chain the service fires the tx as that same EOA). The
  digest the wallet signs is a byte-exact mirror of `geg.core.authz` (locked by
  `apps/admin/src/adminSign.test.ts`).
- The eligibility service here is a **dummy** issuer: it authenticates the voter's wallet
  and, by default, attests any authenticated request. An optional allowlist (`deny path`)
  can gate issuance so only listed wallets get a credential. Swap in a real
  `EligibilityService` (wallet / OIDC / Wahlregister) without changing the apps — the
  attestation wire shape is unchanged.
