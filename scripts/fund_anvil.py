#!/usr/bin/env python3
"""Fund every deployment identity on a local Anvil devnet.

The generated identities (scripts/gen_deploy_env.py) are random keys with zero
balance on a fresh Anvil, so no transaction can pay gas. This derives the address
of every ``*_KEY`` / ``*_SIGNING_KEY`` in the environment and gives each a large
balance via the ``anvil_setBalance`` cheat RPC. Devnet only.

    GEG_CHAIN_RPC=http://anvil:8545 python scripts/fund_anvil.py
"""

from __future__ import annotations

import os

from eth_account import Account
from web3 import Web3

BALANCE_WEI = 10**24  # 1,000,000 ETH


def main() -> None:
    w3 = Web3(Web3.HTTPProvider(os.environ.get("GEG_CHAIN_RPC", "http://127.0.0.1:8545")))
    seen: set[str] = set()
    for name, value in os.environ.items():
        if not (name.endswith("_KEY") or name.endswith("_SIGNING_KEY")) or not value.strip():
            continue
        try:
            addr = Account.from_key(value.strip()).address
        except Exception:  # noqa: BLE001 — not a private key (e.g. a URL) → skip
            continue
        if addr in seen:
            continue
        seen.add(addr)
        w3.provider.make_request("anvil_setBalance", [addr, hex(BALANCE_WEI)])
        print(f"funded {name} → {addr}")
    print(f"funded {len(seen)} account(s)")


if __name__ == "__main__":
    main()
