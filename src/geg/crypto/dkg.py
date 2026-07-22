"""Feldman VSS distributed key generation over G2 (DESIGN.md §5.3, §7.1).

Each keyper draws a random degree-``t`` polynomial, publishes Feldman
commitments ``γ_j = c_j·P2``, and hands share ``φ(i)`` to keyper ``i``. In round 2
every keyper checks each received share against the dealer's commitments
(``s_i·P2 == Σ_j i^j·γ_j``) and, if all pass, forms its combined secret share
``msk_j = Σ_k s_j^(k)``. The joint key is ``mpk = Σ_k γ_0^(k) = msk·P2``.

A fresh DKG runs per election; there is no long-lived master key.
"""

from __future__ import annotations

from geg.crypto.params import CURVE_ORDER
from geg.crypto.points import G2, Z2, add, eq, mul, random_scalar


class KeyperDKGState:
    """One keyper's DKG state machine (round1 → round2 → partial_decrypt)."""

    def __init__(self) -> None:
        self.keyper_id: int | None = None
        self.n: int | None = None
        self.t: int | None = None
        self.coefficients: list[int] | None = None
        self.commitments: list | None = None  # [γ_0..γ_t] as G2 points
        self.shares_for_others: dict[int, int] = {}
        self.combined_share: int | None = None  # msk_j
        self.public_key_share = None  # msk_j·P2

    def round1(self, keyper_id: int, n: int, t: int):
        """Generate polynomial, Feldman commitments, and shares for i = 1..n.

        Returns ``(commitments, shares_dict)``.
        """
        self.keyper_id, self.n, self.t = keyper_id, n, t
        self.coefficients = [random_scalar() for _ in range(t + 1)]
        self.commitments = [mul(G2, c) for c in self.coefficients]
        self.shares_for_others = {}
        for i in range(1, n + 1):
            val, x_power = 0, 1
            for j in range(t + 1):
                val = (val + self.coefficients[j] * x_power) % CURVE_ORDER
                x_power = (x_power * i) % CURVE_ORDER
            self.shares_for_others[i] = val
        return self.commitments, self.shares_for_others

    def round2(self, all_commitments: dict, received_shares: dict):
        """Verify received shares (Feldman VSS) and combine into ``msk_j``.

        Raises ``ValueError`` with a ``bad_dealers`` attribute listing any dealer
        whose share failed ``s_i·P2 == Σ_j my_id^j·γ_j`` — the trigger for the
        signed complaint/reveal flow.
        """
        my_id = self.keyper_id
        bad_dealers = []
        for dealer_id, share in received_shares.items():
            comms = all_commitments[dealer_id]
            expected, x_power = Z2, 1
            for j in range(len(comms)):
                expected = add(expected, mul(comms[j], x_power))
                x_power = (x_power * my_id) % CURVE_ORDER
            if not eq(expected, mul(G2, share)):
                bad_dealers.append(dealer_id)
        if bad_dealers:
            err = ValueError(f"Keyper {my_id}: Feldman VSS failed for dealers {bad_dealers}")
            err.bad_dealers = bad_dealers
            raise err

        self.combined_share = sum(received_shares.values()) % CURVE_ORDER
        self.public_key_share = mul(G2, self.combined_share)
        # Zeroize material no longer needed.
        self.coefficients = None
        self.shares_for_others = {}
        return self.combined_share, self.public_key_share

    def partial_decrypt(self, C1):
        """Partial decryption share ``σ_j = msk_j·C1`` (G2 point)."""
        if self.combined_share is None:
            raise RuntimeError("DKG not completed; cannot decrypt")
        return mul(C1, self.combined_share)


def derive_joint_mpk(all_commitments: dict):
    """Joint master public key ``mpk = Σ_dealer γ_0^(dealer)``."""
    mpk = Z2
    for dealer_id in sorted(all_commitments):
        mpk = add(mpk, all_commitments[dealer_id][0])
    return mpk


def derive_mpk_share(target_keyper_id: int, all_commitments: dict):
    """Per-keyper public share ``mpk_target = Σ_dealer Σ_j target^j·γ_j^(dealer)``.

    This is what is published on the data layer as
    ``committee_pks[target_keyper_id - 1]``.
    """
    mpk_share = Z2
    for dealer_id in sorted(all_commitments):
        comms = all_commitments[dealer_id]
        x_power = 1
        for j in range(len(comms)):
            mpk_share = add(mpk_share, mul(comms[j], x_power))
            x_power = (x_power * target_keyper_id) % CURVE_ORDER
    return mpk_share
