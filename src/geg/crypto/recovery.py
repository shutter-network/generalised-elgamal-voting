"""Threshold combination and discrete-log recovery.

Lagrange-interpolate ``t+1`` partial decryption shares at zero to get
``σ = msk·C1``, then ``τ = C2 − σ = V·P2`` and recover ``V`` by baby-step
giant-step. BSGS cost is ``O(√bound)``; the bound is derived at tally time as
``budget × Σ(admitted weights)`` (:mod:`geg.aggregation` supplies it).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

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


def _key(P) -> bytes:
    return b"\x00" if is_identity(P) else bytes(P.to_compressed_bytes())


@dataclass(frozen=True)
class BabyStepTable:
    """Pre-computed baby steps for one bound, reusable across candidates.

    The table depends only on the generator and ``n = ⌈√max_val⌉``, never on the
    ciphertext being solved, so an election with ``ℓ`` candidates needs exactly one
    — building it per candidate is ``ℓ`` times the work for an identical result.
    """

    max_val: int
    n: int
    neg_step: object  # −n·P2, the giant step
    table: dict  # compressed-bytes → j


def build_baby_step_table(max_val: int) -> BabyStepTable:
    """Build the baby-step table for ``max_val``: ``O(√max_val)`` time and memory.

    Hoist this out of any loop over candidates and pass it to
    :func:`baby_step_giant_step_with_table`. At the sizes a real election reaches
    the build dominates — roughly 11 µs and 218 bytes per entry, so a bound of 1e12
    is ~11 s and ~218 MB — and repeating it per candidate is the single most
    expensive thing a tally can do for no gain. See ``docs/COORDINATOR_SIZING.md``.
    """
    n = int(math.isqrt(max_val)) + 2 if max_val > 0 else 1
    table = {}
    power = Z2
    for j in range(n):
        table[_key(power)] = j
        power = add(power, G2)
    return BabyStepTable(max_val=max_val, n=n, neg_step=neg(mul(G2, n)), table=table)


def baby_step_giant_step_with_table(target, table: BabyStepTable):
    """Look ``target`` up in a pre-built table. Returns ``m`` or ``None``.

    Only the giant-step walk, which is the cheap half: in ``exact`` mode the
    per-candidate totals sum to the bound, so the walks across every candidate
    share one budget of ``≈ n`` steps in total rather than costing ``n`` each.
    """
    if table.max_val == 0:
        return 0 if is_identity(target) else None
    if is_identity(target):
        return 0

    gamma = target
    for i in range(table.n + 1):
        j = table.table.get(_key(gamma))
        if j is not None:
            m = i * table.n + j
            if m <= table.max_val:
                return m
        gamma = add(gamma, table.neg_step)
    return None


def baby_step_giant_step(target, max_val: int):
    """Return ``m`` in ``[0, max_val]`` with ``m·P2 == target``, or ``None``.

    Builds a throwaway table. Fine for a single lookup; for more than one against
    the same bound use :func:`build_baby_step_table` and
    :func:`baby_step_giant_step_with_table` instead.
    """
    if max_val == 0:
        return 0 if is_identity(target) else None
    if is_identity(target):
        return 0
    return baby_step_giant_step_with_table(target, build_baby_step_table(max_val))


def threshold_decrypt(C1, C2, shares, max_val: int):
    """Full threshold decryption: combine shares, subtract, BSGS-recover.

    ``shares`` is ``[(keyper_id, sigma_i)]``. Returns plaintext ``m`` or ``None``.
    """
    sigma = combine_shares(shares)
    tau = add(C2, neg(sigma))  # τ = m·P2
    return baby_step_giant_step(tau, max_val)
