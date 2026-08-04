#!/usr/bin/env python3
"""Generate a consistent deployment identity set + sample election config.

**Local / testing convenience — NOT a production tool.** It mints ALL identities
(including the keypers' private keys) in one place so a single machine can run the
whole stack for demos and the RUNNING.md walkthroughs. A real deployment does the
opposite: each keyper operator holds their own key on their own machine and only
shares their address; the admin builds the election config from those addresses via
proper key management, and fills a real ``deploy/.env`` from ``.env.example`` by
hand. Do not use the keys this emits for anything real — they are throwaway.

Its reason to exist is *coherence*: these secp256k1 identities are cross-referential
and hand-authoring them consistently is error-prone — each keyper's
``KEYPER_SIGNING_KEY`` must match its ``signing_key`` in the election config, the
coordinator's key must produce the ``COORDINATOR_IDENTITY`` keypers pin, and the
eligibility private key must match the config's eligibility public key. This wires
it all up in one shot:

    python scripts/gen_deploy_env.py

Writes (under ``deploy/``, relative to repo root):
  * ``.env``                 — admin/operator-stack keys + tokens (the coordinator key
                               doubles as the chain relayer + result publisher)
  * ``.env.keyper{1,2,3}``   — one self-contained env per keyper stack (its key,
                               pinned coordinator address, port, state dir)
  * ``sample-election.json`` — a valid config envelope wiring the keyper
                               URLs/addresses, admin/gateway/coordinator (result
                               publisher) identities, and a fresh eligibility key

The eligibility *private* key goes in ``.env`` (whoever issues voter attestations
needs it). Voting window is set relative to "now" so the sample is immediately
registrable.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from eth_account import Account

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant  # noqa: E402
from geg.crypto import schnorr  # noqa: E402
from geg.crypto.points import g1_to_compressed  # noqa: E402
from geg.envelopes import codecs  # noqa: E402

N_KEYPERS = 3
T = 1  # (t, n) = (1, 3): any 2 of 3 decrypt


def _key():
    acct = Account.create()
    return acct.key.hex(), acct.address  # (0x-hex privkey, 0x checksummed address)


def main() -> None:
    admin_sk, admin_addr = _key()
    gw_sk, gw_addr = _key()
    coord_sk, coord_addr = _key()  # coordinator: bootstrap identity + result publisher + chain relayer
    keypers = [_key() for _ in range(N_KEYPERS)]

    # Keyper URLs (config.keypers[].url). Keypers run as SEPARATE stacks
    # now, so these must be URLs everyone can reach — NOT internal Docker DNS.
    # Default: host-published ports for local split testing (keyper N at
    # host.docker.internal:810N). Override with KEYPER_URLS=url1,url2,url3 for a
    # real multi-machine deploy (each operator's public URL).
    _url_override = [u.strip() for u in os.environ.get("KEYPER_URLS", "").split(",") if u.strip()]

    def _keyper_url(idx0: int) -> str:
        return _url_override[idx0] if _url_override else f"http://host.docker.internal:{8101 + idx0}"

    elig_sk, elig_vk = schnorr.keygen()
    elig_pub = g1_to_compressed(elig_vk)

    # Window offsets (seconds from now) — overridable for a short real-time demo:
    #   VOTING_START_OFFSET=60 VOTING_DURATION=90
    now = int(time.time())
    start_off = int(os.environ.get("VOTING_START_OFFSET", "300"))   # leave time to run DKG
    duration = int(os.environ.get("VOTING_DURATION", "3300"))
    voting_start = now + start_off
    voting_end = voting_start + duration
    cfg = ElectionConfig(
        election_id=b"\x00" * 32,  # placeholder — the registry assigns the id at register
        num_candidates=3,
        budget=3,
        mode=Mode.EXACT,
        variant=Variant.A,
        weighted=True,
        max_weight=10,
        duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=voting_start,
        voting_end=voting_end,
        threshold=Threshold(t=T, n=N_KEYPERS),
        keypers=tuple(
            KeyperIdentity(signing_key=bytes.fromhex(addr[2:]), url=_keyper_url(i))
            for i, (_sk, addr) in enumerate(keypers)
        ),
        eligibility_key=elig_pub,
        result_publisher_key=bytes.fromhex(coord_addr[2:]),  # the coordinator publishes the result
        gateway_keys=(bytes.fromhex(gw_addr[2:]),),
        admin_key=bytes.fromhex(admin_addr[2:]),
        protocol_version="v1",
    )

    out = REPO / "deploy"
    out.mkdir(exist_ok=True)

    coordinator_api_token = secrets.token_urlsafe(32)  # shared: coordinator relay ↔ keypers

    (out / "sample-election.json").write_text(json.dumps(codecs.enc_config(cfg), indent=2) + "\n")

    # Comments live on their own lines (never inline after a value) so the file
    # parses cleanly with `source`/`grep|cut`, not just docker compose --env-file.
    env_lines = [
        "# Generated by scripts/gen_deploy_env.py — one coherent identity set.",
        "# Private keys are secrets; this file is git-ignored. Do NOT commit.",
        "",
        "# The admin EOA: registers/cancels; on chain the adminAddr; and the key the admin",
        "# wallet signs register/cancel with (auth model B — no bearer token).",
        f"ADMIN_SIGNING_KEY={admin_sk}",
        f"GATEWAY_SIGNING_KEY={gw_sk}",
        "# Coordinator identity: the address keypers pin for bootstrap, the config's",
        "# result_publisher_key (signs the result), AND — on chain — the funded account",
        "# that relays keyper meta-tx and sends publishResult (holds RESULT_PUBLISHER_ROLE).",
        f"COORDINATOR_SIGNING_KEY={coord_sk}",
        f"# coordinator address (give to keyper operators out-of-band): {coord_addr.lower()}",
        "# Bearer token keypers present to the coordinator's write-relay endpoints.",
        f"COORDINATOR_API_TOKEN={coordinator_api_token}",
        "",
        "# Keypers run as SEPARATE stacks — their private keys + the pinned coordinator",
        "# address live in deploy/.env.keyper{1,2,3} (also generated), NOT here.",
        "",
        "# Blockchain backend only (the coordinator's account above is the gas-paying",
        "# relayer for keyper meta-tx and the result publisher):",
        "# GEG_CHAIN_RPC=http://anvil:8545",
        "# GEG_REGISTRY_ADDRESS=0x...   (set after deploying the registry — see RUNNING.md)",
        "",
        "# Eligibility service secret — issues voter attestations (its public key is",
        "# the config's eligibility_key). In production the eligibility service holds",
        "# this; here it lets scripts/vote_sample.py issue attestations for the demo.",
        f"ELIGIBILITY_PRIVATE_KEY={hex(elig_sk)}",
        "",
    ]
    (out / ".env").write_text("\n".join(env_lines))

    # Per-keyper operator env files (one self-contained env per keyper stack) — this
    # is where each keyper's private key + the pinned coordinator address live. The
    # admin URLs default to host.docker.internal (correct for local split testing); a
    # real operator on their own machine edits them, or starts from .env.keyper.example.
    keyper_env_files = []
    for i, (sk, _addr) in enumerate(keypers):
        port = urlparse(_keyper_url(i)).port or 8100  # match this keyper's config url
        (out / f".env.keyper{i + 1}").write_text("\n".join([
            f"# keyper{i + 1} operator env — generated by gen_deploy_env.py.",
            f"KEYPER_SIGNING_KEY={sk}",
            f"COORDINATOR_IDENTITY={coord_addr.lower()}",
            "# (relay bearer token is NOT here — the coordinator pushes it via /auth/bootstrap)",
            "GEG_DATA_LAYER_URL=http://host.docker.internal:8000",
            "COORDINATOR_URL=http://host.docker.internal:8400",
            f"KEYPER_PORT={port}",
            f"KEYPER_STATE_DIR_HOST=./keyper-state{i + 1}",
            "",
        ]))
        keyper_env_files.append(f".env.keyper{i + 1}")

    print(f"wrote {out/'.env'}")
    print(f"wrote {out/'sample-election.json'}")
    for f in keyper_env_files:
        print(f"wrote {out/f}")
    print(f"admin={admin_addr} gateway={gw_addr}")
    print(f"coordinator={coord_addr}  (result publisher + chain relayer)")
    for i, (_sk, addr) in enumerate(keypers, start=1):
        print(f"keyper{i}={addr}")


if __name__ == "__main__":
    main()
