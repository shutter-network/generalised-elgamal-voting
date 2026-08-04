# geg frontends

Two React + Vite browser apps and a shared multi-election dashboard. See
[`PLAN.md`](./PLAN.md) for the design.

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
- A running geg stack with the **public API**, **gateway**, **admin**, and the
  **eligibility** service reachable (see the repo's `RUNNING.md`; the eligibility service
  is in `deploy/docker-compose.{db,chain-devnet}.yml` on `:8600`).

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

`VITE_API_URL` (8500), `VITE_GATEWAY_URL` (8200), `VITE_ADMIN_URL` (8300),
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
  EOA (`config.admin_key`). Then register (form or paste a `deploy/sample-election.json`
  config) / cancel; each action is authorized by a wallet signature (no token).
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
- The eligibility service here is a **dummy** issuer (attests any request). Swap in a
  real `EligibilityService` (wallet / OIDC / Wahlregister) without changing the apps —
  the attestation wire shape is unchanged.
