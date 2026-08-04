# blst wasm assets

`@shutter-network/urban-verified-crypto` loads `blst.js` + `blst.wasm` at
`initCurves()` (served from `/blst.js`, `/blst.wasm`).

These are **copied here automatically** by the voter app's `postinstall` script (a
plain `cp` from the SDK's own `dist/`, see `package.json`), so `npm install` sets them
up. They are generated (git-ignored), not source. If they go missing, re-run
`npm install` (or `npm run postinstall -w @geg/voter`).

> This project has prior history of a *nondeterministic ballot-verification* bug rooted
> in a two-layer WASM memory issue. If ballots intermittently fail the gateway filter,
> suspect the blst build; confirm a locally-built ballot verifies reproducibly.
