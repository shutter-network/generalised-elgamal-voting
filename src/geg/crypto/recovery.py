"""Threshold combination and discrete-log recovery (DESIGN.md §6.3, §8.3).

Lagrange-interpolate ``t+1`` partial decryption shares at zero to get
``σ = msk·C1``, then ``τ = C2 − σ = V·P2`` and recover ``V`` by baby-step
giant-step. BSGS cost is ``O(√bound)``; the bound is derived at tally time as
``budget × Σ(admitted weights)`` (:mod:`geg.aggregation` supplies it).
"""

from __future__ import annotations

import math

from geg.crypto.params import CURVE_ORDER
from geg.crypto.points import G2, Z2, add, is_identity, mul, neg


def lagrange_coefficient(j_id: int, all_ids, q: int = CURVE_ORDER) -> int:
    """λ_j = Π_{k≠j} (0 − k)/(j − k) mod q, for interpolation at x = 0."""
    num, den = 1, 1
    for k_id in all_ids:
        if k_id == j_id:
            continue
        num = (num * (0 - k_id)) % q
        den = (den * (j_id - k_id)) % q
    return (num * pow(den, -1, q)) % q


def combine_shares(shares) -> object:
    """Lagrange-combine ``[(keyper_id, sigma_i)]`` into ``σ = msk·C1`` (G2)."""
    all_ids = [kid for kid, _ in shares]
    result = Z2
    for j_id, sigma_j in shares:
        lam = lagrange_coefficient(j_id, all_ids)
        result = add(result, mul(sigma_j, lam))
    return result


def baby_step_giant_step(target, max_val: int):
    """Return ``m`` in ``[0, max_val]`` with ``m·P2 == target``, or ``None``."""
    if max_val == 0:
        return 0 if is_identity(target) else None
    if is_identity(target):
        return 0

    n = int(math.isqrt(max_val)) + 2

    def _key(P):
        return b"\x00" if is_identity(P) else bytes(P.to_compressed_bytes())

    table = {}
    power = Z2
    for j in range(n):
        table[_key(power)] = j
        power = add(power, G2)

    neg_step = neg(mul(G2, n))
    gamma = target
    for i in range(n + 1):
        key = _key(gamma)
        if key in table:
            m = i * n + table[key]
            if m <= max_val:
                return m
        gamma = add(gamma, neg_step)
    return None


def threshold_decrypt(C1, C2, shares, max_val: int):
    """Full threshold decryption: combine shares, subtract, BSGS-recover.

    ``shares`` is ``[(keyper_id, sigma_i)]``. Returns plaintext ``m`` or ``None``.
    """
    sigma = combine_shares(shares)
    tau = add(C2, neg(sigma))  # τ = m·P2
    return baby_step_giant_step(tau, max_val)
