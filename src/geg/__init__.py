"""Generalised Threshold ElGamal Voting.

A storage-agnostic, privacy-preserving voting protocol built on linearly
homomorphic threshold ElGamal over BLS12-381.

This package is the generalisation layer: ports (``geg.ports``), wire envelopes
(``geg.envelopes``), and — in later slices — adapters and services. The crypto
core and byte formats are adopted by reference from an existing BLS12-381
threshold-ElGamal crypto suite (a TypeScript SDK and its Python mirror).
"""

__version__ = "0.1.0"
