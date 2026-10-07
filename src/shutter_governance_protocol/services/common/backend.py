"""Client-side backend selection for deployed services.

A service (admin, gateway, coordinator) picks its ``ElectionDataLayer``
from ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER`` so the *same* daemon runs on any backend:

* ``memory`` / ``database`` — :class:`~shutter_governance_protocol.adapters.db.client.HttpDataLayerClient`
  pointed at the uniform data-layer service (``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL``). The service
  verifies the actor's request signature and writes.
* ``blockchain`` — a chain-direct :class:`~shutter_governance_protocol.adapters.chain.client.BlockchainDataLayer`
  bound to the actor's **own** Ethereum key, so the actor's write is its own
  transaction (``msg.sender`` authz, per the chain's tx-sender model). Env:
  ``SHUTTER_GOVERNANCE_PROTOCOL_CHAIN_RPC``, ``SHUTTER_GOVERNANCE_PROTOCOL_REGISTRY_ADDRESS``, plus the role's own key.

Keypers are the deliberate exception: they never hold a chain key. Their
content-signed DKG/aggregate/decryption writes are relayed by the coordinator, whose
account pays gas and sends the ``...Signed`` tx while the contract ``ecrecover``s the
keyper as author — so the keyper process keeps talking to ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL`` (reads)
and the coordinator relay (writes) on every backend.
"""

from __future__ import annotations

import os

_HTTP_BACKENDS = {"memory", "in-memory", "inmemory", "database", "db", "postgres", "postgresql"}
_CHAIN_BACKENDS = {"blockchain", "chain", "eth"}


def data_layer_for_service(role_key_hex: str | None = None):
    """Return the adapter this service should hold, per ``SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER``.

    ``role_key_hex`` is the actor's own Ethereum private key (hex); used only on
    the blockchain backend as the tx sender. ``None`` yields a read-only chain
    adapter (e.g. the coordinator, which only reads + orchestrates over HTTP).
    """
    backend = os.environ.get("SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER", "database").strip().lower()

    if backend in _HTTP_BACKENDS:
        from shutter_governance_protocol.adapters.db.client import HttpDataLayerClient

        return HttpDataLayerClient(os.environ["SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER_URL"])

    if backend in _CHAIN_BACKENDS:
        from eth_account import Account
        from web3 import Web3

        from shutter_governance_protocol.adapters.chain.client import BlockchainDataLayer

        w3 = Web3(Web3.HTTPProvider(os.environ["SHUTTER_GOVERNANCE_PROTOCOL_CHAIN_RPC"]))
        registry = os.environ["SHUTTER_GOVERNANCE_PROTOCOL_REGISTRY_ADDRESS"]
        account = Account.from_key(role_key_hex) if role_key_hex else None
        return BlockchainDataLayer(w3, registry, account)

    raise SystemExit(f"unknown SHUTTER_GOVERNANCE_PROTOCOL_DATA_LAYER={backend!r} (want memory|database|blockchain)")
