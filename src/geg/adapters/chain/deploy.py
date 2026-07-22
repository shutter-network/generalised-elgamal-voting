"""Deployment + Anvil helpers for the blockchain adapter (test + real-deploy).

Reads compiled bytecode from the Foundry ``contracts/out/`` artifacts, deploys the
registry, and offers Anvil devnet controls (time warp, state reset) used by the
conformance/e2e fixtures.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from web3 import Web3

from geg.adapters.chain.client import REGISTRY_ABI

_REPO_ROOT = Path(__file__).parents[4]
_CONTRACTS_OUT = Path(os.environ.get("GEG_CONTRACTS_OUT", _REPO_ROOT / "contracts" / "out"))


def bytecode_of(name: str) -> str:
    artifact = json.loads((_CONTRACTS_OUT / f"{name}.sol" / f"{name}.json").read_text())
    return artifact["bytecode"]["object"]


def send_tx(w3: Web3, account, built_fn):
    """Sign+send a contract function/constructor call; return the receipt."""
    gas = built_fn.estimate_gas({"from": account.address})
    tx = built_fn.build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": int(gas * 12 // 10),
        "gasPrice": w3.eth.gas_price,
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)


def deploy_registry(w3: Web3, account) -> str:
    """Deploy an ElectionRegistry with ``account`` as DEFAULT_ADMIN_ROLE."""
    registry = w3.eth.contract(abi=REGISTRY_ABI, bytecode=bytecode_of("ElectionRegistry"))
    receipt = send_tx(w3, account, registry.constructor(account.address))
    return receipt.contractAddress


# -- Anvil devnet controls -------------------------------------------------- #

def anvil_set_time(w3: Web3, timestamp: int) -> None:
    """Warp the devnet clock: the next block is mined exactly at ``timestamp``."""
    w3.provider.make_request("evm_setNextBlockTimestamp", [timestamp])
    w3.provider.make_request("evm_mine", [])


def anvil_reset(w3: Web3) -> None:
    """Reset devnet state to genesis (fresh per-test isolation)."""
    w3.provider.make_request("anvil_reset", [{}])


def chain_now(w3: Web3):
    """A clock callable returning the latest block timestamp (chain time)."""
    return int(w3.eth.get_block("latest")["timestamp"])
