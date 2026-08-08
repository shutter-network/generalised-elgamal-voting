#!/usr/bin/env python3
"""Deploy an ElectionRegistry to a chain and print its address.

The registry's deployer becomes its ``DEFAULT_ADMIN_ROLE`` and thus the only
account that may register elections — so deploy it with the **admin** key.

    GEG_CHAIN_RPC=http://anvil:8545 ADMIN_SIGNING_KEY=0x... \
      GEG_CONTRACTS_OUT=/contracts-out python scripts/deploy_registry.py

Needs the Foundry artifacts (``forge build`` in contracts/) reachable via
``GEG_CONTRACTS_OUT`` (defaults to contracts/out).

On the Anvil devnet this runs automatically as a ``docker compose`` dependency
(admin = pre-funded Anvil account [0], fresh chain → the registry lands at a
**deterministic** address). Two guards make that safe and idempotent:

* if ``GEG_REGISTRY_ADDRESS`` is set and already has code, it is **already
  deployed** — skip (so re-``up`` doesn't redeploy and shift the address);
* otherwise deploy, and if ``GEG_REGISTRY_ADDRESS`` is set, **assert** the
  deployed address equals it (a mismatch means the determinism assumption broke —
  a changed admin key / deploy order / non-fresh chain — fail loudly, don't leave
  the services pointing at the wrong address).

With ``GEG_REGISTRY_ADDRESS`` unset (e.g. a real chain, deployed out of band) it
just deploys and prints the address to copy into your env.
"""

from __future__ import annotations

import os
import sys

from eth_account import Account
from web3 import Web3

from geg.adapters.chain.deploy import deploy_registry


def main() -> None:
    w3 = Web3(Web3.HTTPProvider(os.environ.get("GEG_CHAIN_RPC", "http://127.0.0.1:8545")))
    admin = Account.from_key(os.environ["ADMIN_SIGNING_KEY"])
    expected = os.environ.get("GEG_REGISTRY_ADDRESS", "").strip()

    # Idempotent: if the expected address already has contract code, it's deployed.
    if expected and w3.eth.get_code(Web3.to_checksum_address(expected)):
        print(f"GEG_REGISTRY_ADDRESS={expected} (already deployed — skipping)")
        return

    address = deploy_registry(w3, admin)
    if expected and expected.lower() != address.lower():
        sys.exit(
            f"deployed registry {address} != expected GEG_REGISTRY_ADDRESS {expected}.\n"
            "The devnet auto-deploy assumes admin = the pre-funded Anvil account [0] deploying "
            "to a FRESH chain (registry at a deterministic address). Did you change the admin "
            "key, the deploy order, or reuse a non-fresh chain?"
        )
    print(f"GEG_REGISTRY_ADDRESS={address}")


if __name__ == "__main__":
    main()
