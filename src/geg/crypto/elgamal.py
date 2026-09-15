"""Linearly homomorphic exponential ElGamal in G2.

``Enc(m, mpk, r) = (r·P2, r·mpk + m·P2)``. Homomorphic by point-wise addition:
``Enc(m1) + Enc(m2) = Enc(m1 + m2)``; ``scalar_mul_ct(k, ct) = Enc(k·m)`` applies
a voter weight. Decryption recovers small ``m`` by discrete-log
(:mod:`geg.crypto.recovery`).
"""

from __future__ import annotations

from geg.crypto.points import G2, Z2, add, mul, random_scalar

# A ciphertext is a pair of G2 points ``(C1, C2)``. We keep it as a plain tuple
# at the crypto layer; the envelope layer wraps it in a typed dataclass.
Ciphertext = tuple  # (G2Point, G2Point)


def encrypt(mpk, m: int, r: int | None = None) -> tuple[object, object, int]:
    """Encrypt ``m`` under ``mpk``. Returns ``(C1, C2, r)``.

    ``r`` (the randomness) is returned because the voter needs it to build the
    range and budget proofs. An explicit ``r`` supports deterministic vectors.
    """
    if r is None:
        r = random_scalar()
    c1 = mul(G2, r)
    c2 = add(mul(mpk, r), mul(G2, m))
    return c1, c2, r


def add_ct(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    """Homomorphic sum of two ciphertexts (component-wise EC addition)."""
    return add(a[0], b[0]), add(a[1], b[1])


def scalar_mul_ct(k: int, a: Ciphertext) -> Ciphertext:
    """``k · Enc(m) = Enc(k·m)`` — applies a weight to a ballot ciphertext."""
    return mul(a[0], k), mul(a[1], k)


def sum_cts(cts) -> Ciphertext:
    """Homomorphic sum of a list of ciphertexts (identity for empty)."""
    c1_sum, c2_sum = Z2, Z2
    for c1, c2 in cts:
        c1_sum = add(c1_sum, c1)
        c2_sum = add(c2_sum, c2)
    return c1_sum, c2_sum
