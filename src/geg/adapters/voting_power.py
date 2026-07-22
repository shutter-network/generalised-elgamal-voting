"""Chain-backed voting-power source for the wallet eligibility adapter (DESIGN.md §5.2).

The wallet adapter reads voting power through an injected ``address_bytes -> int``
callable. :func:`chain_voting_power` fills that seam with an on-chain read —
``balanceOf`` (ERC20) or ``getVotes`` (ERC20Votes / Snapshot-style) on a token or
strategy contract, optionally at a fixed block (so power is snapshotted at, e.g.,
``voting_start``). This is what maps the Snapshot X "read voting power from chain
state" behaviour onto the generalised eligibility port without any protocol change.
"""

from __future__ import annotations

from typing import Callable

from web3 import Web3

# Minimal ABI covering the two common voting-power shapes.
VOTING_POWER_ABI = [
    {
        "type": "function",
        "name": "balanceOf",
        "stateMutability": "view",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "getVotes",
        "stateMutability": "view",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
]


def chain_voting_power(
    w3: Web3,
    token_address: str,
    *,
    method: str = "balanceOf",
    block_identifier: int | str = "latest",
    abi: list | None = None,
) -> Callable[[bytes], int]:
    """Return an ``address_bytes -> int`` voting-power reader backed by chain state.

    ``method`` selects the getter (``"balanceOf"`` for ERC20, ``"getVotes"`` for
    ERC20Votes). ``block_identifier`` pins the snapshot block (e.g. the election's
    voting-start block) so voting power cannot shift mid-election; ``"latest"`` by
    default. ``abi`` overrides the minimal built-in ABI for a custom contract.
    """
    contract = w3.eth.contract(address=Web3.to_checksum_address(token_address), abi=abi or VOTING_POWER_ABI)
    getter = getattr(contract.functions, method)

    def read(address_bytes: bytes) -> int:
        addr = Web3.to_checksum_address(bytes(address_bytes))
        return int(getter(addr).call(block_identifier=block_identifier))

    return read
