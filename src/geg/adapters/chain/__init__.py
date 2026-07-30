"""Blockchain data-layer adapter.

A single ``BlockchainDataLayer`` per actor, bound to that actor's Ethereum key,
mapping the ``ElectionDataLayer`` port onto the extended bulletin-board contracts
(``contracts/``). Unlike the database adapter there is no server to build — the
chain *is* the server; ordering, roles/authz (tx sender), config immutability, and
the DKG finalization quorum come from the contracts natively. The adapter adds a
thin emulation layer (reading chain state before writes) so it presents the exact
uniform port semantics (idempotent resend, divergent-write rejection) the
conformance suite asserts.

* :mod:`geg.adapters.chain.codec`  — enum + envelope↔contract-struct conversions.
* :mod:`geg.adapters.chain.client` — ``BlockchainDataLayer``.
* :mod:`geg.adapters.chain.deploy` — deploy KeyperSet/Registry + publish, and the
  per-actor adapter factory (test + real-deploy helper).
"""
