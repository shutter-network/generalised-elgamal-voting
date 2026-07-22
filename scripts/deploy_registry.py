#!/usr/bin/env python3
"""Deploy an ElectionRegistry to a chain and print its address.

The registry's deployer becomes its ``DEFAULT_ADMIN_ROLE`` and thus the only
account that may register elections — so deploy it with the **admin** key. Copy
the printed address into ``deploy/.env`` as ``GEG_REGISTRY_ADDRESS`` before
bringing the chain stack up (RUNNING.md).

    GEG_CHAIN_RPC=http://anvil:8545 ADMIN_SIGNING_KEY=0x... \
      GEG_CONTRACTS_OUT=/contracts-out python scripts/deploy_registry.py

Needs the Foundry artifacts (``forge build`` in contracts/) reachable via
``GEG_CONTRACTS_OUT`` (defaults to contracts/out).
"""

from __future__ import annotations

import os

from eth_account import Account
from web3 import Web3

from geg.adapters.chain.deploy import deploy_registry


def main() -> None:
    w3 = Web3(Web3.HTTPProvider(os.environ.get("GEG_CHAIN_RPC", "http://127.0.0.1:8545")))
    admin = Account.from_key(os.environ["ADMIN_SIGNING_KEY"])
    address = deploy_registry(w3, admin)
    print(f"GEG_REGISTRY_ADDRESS={address}")


if __name__ == "__main__":
    main()
