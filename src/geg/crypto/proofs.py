"""Fiat-Shamir sigma proofs over the shared transcript.

All proofs are Fiat-Shamir transforms driven by a shared :class:`Transcript`;
prover and verifier must seed it identically. Byte-faithful to the SDK
(``proofs.ts`` / ``decrypt.ts``):

* **DLEQ (Chaum-Pedersen)** over two G2 bases — proves equal discrete logs.
* **(B+1)-branch OR** — proves a ciphertext encrypts one of ``{m_0..m_B}``;
  used for Variant-A range proofs and the ``atMost`` budget proof.
* **Budget proofs** — ``exact`` (DLEQ that the homomorphic sum encrypts exactly
  ``B``) and ``atMost`` (OR over ``{0..B}`` on the sum).
* **Decryption-share DLEQ** — binds ``sigma = msk_k·C1`` to the committee key.

Wire form of every DLEQ is only ``(e, z)``; commitments are recomputed by the
verifier. The OR proof keeps ``(a1, a2, e, z)`` per branch on the wire (256 bytes).
"""

from __future__ import annotations

from dataclasses import dataclass

from geg.crypto.params import (
    CURVE_ORDER,
    DLEQ_BYTES,
    ONCHAIN_DECRYPT_LABEL,
    scalar_to_bytes,
    u16be,
)
from geg.crypto.points import G2, add, eq, mul, random_scalar
from geg.crypto.transcript import Transcript


def make_decrypt_transcript(election_id: bytes, candidate_index: int) -> Transcript:
    """Freshly seed the decryption-share transcript.

    ``Transcript(SHUTTER-VOTE-DECRYPT-v1)`` with ``electionId`` (32 bytes) and
    ``candidate`` (u16BE) appended. Prover (keyper) and verifier (coordinator /
    auditor) MUST seed identically.
    """
    if len(election_id) != 32:
        raise ValueError(f"election_id must be 32 bytes (got {len(election_id)})")
    if not (0 <= candidate_index < 1 << 16):
        raise ValueError(f"candidate_index {candidate_index} out of u16 range")
    t = Transcript(ONCHAIN_DECRYPT_LABEL)
    t.append("electionId", election_id)
    t.append("candidate", u16be(candidate_index))
    return t


# --------------------------------------------------------------------------- #
#  DLEQ wire codec (64 bytes: e || z)
# --------------------------------------------------------------------------- #

def encode_dleq(e: int, z: int) -> bytes:
    return scalar_to_bytes(e) + scalar_to_bytes(z)


def decode_dleq(b: bytes) -> tuple[int, int]:
    if len(b) != DLEQ_BYTES:
        raise ValueError(f"Expected {DLEQ_BYTES}-byte DLEQ, got {len(b)}")
    return int.from_bytes(b[:32], "big"), int.from_bytes(b[32:], "big")


# --------------------------------------------------------------------------- #
#  DLEQ on G2 (Chaum-Pedersen)
# --------------------------------------------------------------------------- #

def _bind_statement_dleq(t: Transcript, base1, point1, base2, point2) -> None:
    t.append_point("dleq:base1", base1)
    t.append_point("dleq:base2", base2)
    t.append_point("dleq:point1", point1)
    t.append_point("dleq:point2", point2)


def prove_dleq(base1, point1, base2, point2, x: int, t: Transcript, *, w: int | None = None):
    """Prove ``log_base1(point1) == log_base2(point2) == x``. Returns ``(e, z)``."""
    if w is None:
        w = random_scalar()
    a1 = mul(base1, w)
    a2 = mul(base2, w)
    _bind_statement_dleq(t, base1, point1, base2, point2)
    t.append_point("dleq:a1", a1)
    t.append_point("dleq:a2", a2)
    e = t.challenge("dleq:e")
    z = (w + x * e) % CURVE_ORDER
    return e, z


def verify_dleq(base1, point1, base2, point2, e: int, z: int, t: Transcript) -> bool:
    a1 = add(mul(base1, z), mul(point1, (-e) % CURVE_ORDER))
    a2 = add(mul(base2, z), mul(point2, (-e) % CURVE_ORDER))
    _bind_statement_dleq(t, base1, point1, base2, point2)
    t.append_point("dleq:a1", a1)
    t.append_point("dleq:a2", a2)
    return e == t.challenge("dleq:e")


# --------------------------------------------------------------------------- #
#  Decryption-share DLEQ (proves sigma = msk_k·C1 under committee key mpk_k)
# --------------------------------------------------------------------------- #

def _bind_decryption_share(t: Transcript, C1, C2, mpk_k, keyper_index: int) -> None:
    t.append_point("dec:C1", C1)
    t.append_point("dec:C2", C2)
    t.append_point("dec:mpk_k", mpk_k)
    t.append("dec:keyperIndex", u16be(keyper_index))


def prove_decryption_share(t: Transcript, C1, C2, mpk_k, sigma, msk_k: int, keyper_index: int):
    """DLEQ that ``dlog_P2(mpk_k) == dlog_C1(sigma) == msk_k``. Returns ``(e, z)``."""
    _bind_decryption_share(t, C1, C2, mpk_k, keyper_index)
    return prove_dleq(G2, mpk_k, C1, sigma, msk_k, t)


def verify_decryption_share(t: Transcript, C1, C2, mpk_k, sigma, e: int, z: int, keyper_index: int) -> bool:
    _bind_decryption_share(t, C1, C2, mpk_k, keyper_index)
    return verify_dleq(G2, mpk_k, C1, sigma, e, z, t)


# --------------------------------------------------------------------------- #
#  (B+1)-branch OR proof
# --------------------------------------------------------------------------- #

@dataclass
class ORBranch:
    a1: object
    a2: object
    e: int
    z: int


def _bind_statement_or(t: Transcript, c1, c2, mpk, candidates) -> None:
    t.append_point("or:P2", G2)
    t.append_point("or:mpk", mpk)
    t.append_point("or:C1", c1)
    t.append_point("or:C2", c2)
    t.append("or:|M|", len(candidates).to_bytes(4, "big"))
    for i, m in enumerate(candidates):
        t.append_scalar(f"or:m[{i}]", m % CURVE_ORDER)


def prove_or(c1, c2, mpk, candidates, r: int, true_index: int, t: Transcript, *,
             w: int | None = None, simulated=None) -> list[ORBranch]:
    """OR proof that ``(c1, c2)`` encrypts ``candidates[true_index]``.

    ``w`` and ``simulated`` (per-branch ``(e, z)``, ``None`` at the real branch)
    are exposed to reproduce fixtures deterministically.
    """
    n = len(candidates)
    if n == 0:
        raise ValueError("prove_or: candidate set is empty")
    if not (0 <= true_index < n):
        raise ValueError(f"prove_or: true_index {true_index} out of [0, {n})")
    if simulated is None:
        simulated = [None] * n
    if len(simulated) != n:
        raise ValueError(f"prove_or: simulated length {len(simulated)} != candidates {n}")

    branches: list[ORBranch] = [ORBranch(None, None, 0, 0) for _ in range(n)]
    real_w = w if w is not None else random_scalar()
    for i in range(n):
        if i == true_index:
            branches[i] = ORBranch(mul(G2, real_w), mul(mpk, real_w), 0, 0)
        else:
            sim = simulated[i] if simulated[i] is not None else (random_scalar(), random_scalar())
            ei, zi = sim[0] % CURVE_ORDER, sim[1] % CURVE_ORDER
            Di = add(c2, mul(G2, (-(candidates[i] % CURVE_ORDER)) % CURVE_ORDER))
            a1 = add(mul(G2, zi), mul(c1, (-ei) % CURVE_ORDER))
            a2 = add(mul(mpk, zi), mul(Di, (-ei) % CURVE_ORDER))
            branches[i] = ORBranch(a1, a2, ei, zi)

    _bind_statement_or(t, c1, c2, mpk, candidates)
    for i in range(n):
        t.append_point(f"or:a1[{i}]", branches[i].a1)
        t.append_point(f"or:a2[{i}]", branches[i].a2)
    e_total = t.challenge("or:e")

    sim_sum = sum(branches[i].e for i in range(n) if i != true_index)
    e_real = (e_total - sim_sum) % CURVE_ORDER
    z_real = (real_w + r * e_real) % CURVE_ORDER
    branches[true_index].e = e_real
    branches[true_index].z = z_real
    return branches


def verify_or(c1, c2, mpk, candidates, branches, t: Transcript) -> bool:
    n = len(candidates)
    if len(branches) != n:
        return False
    for i, br in enumerate(branches):
        if not eq(mul(G2, br.z), add(br.a1, mul(c1, br.e))):
            return False
        Di = add(c2, mul(G2, (-(candidates[i] % CURVE_ORDER)) % CURVE_ORDER))
        if not eq(mul(mpk, br.z), add(br.a2, mul(Di, br.e))):
            return False
    _bind_statement_or(t, c1, c2, mpk, candidates)
    for i, br in enumerate(branches):
        t.append_point(f"or:a1[{i}]", br.a1)
        t.append_point(f"or:a2[{i}]", br.a2)
    return sum(br.e for br in branches) % CURVE_ORDER == t.challenge("or:e")


# --------------------------------------------------------------------------- #
#  Budget proofs
# --------------------------------------------------------------------------- #

def bind_budget(t: Transcript, B: int, mode: str) -> None:
    if mode not in ("exact", "atMost"):
        raise ValueError(f"unknown budget mode: {mode}")
    t.append("budget:mode", b"\x00" if mode == "exact" else b"\x01")
    t.append_scalar("budget:B", B % CURVE_ORDER)


def _budget_dleq_instance(c1_sum, c2_sum, mpk, B: int):
    # point2 = c2_sum - B·P2 = r_sum·mpk when the sum encrypts exactly B.
    D = add(c2_sum, mul(G2, (-(B % CURVE_ORDER)) % CURVE_ORDER))
    return G2, c1_sum, mpk, D  # base1, point1, base2, point2


def prove_budget_exact(c1_sum, c2_sum, mpk, B: int, r_sum: int, t: Transcript, *, w=None):
    bind_budget(t, B, "exact")
    base1, point1, base2, point2 = _budget_dleq_instance(c1_sum, c2_sum, mpk, B)
    return prove_dleq(base1, point1, base2, point2, r_sum, t, w=w)


def verify_budget_exact(c1_sum, c2_sum, mpk, B: int, e: int, z: int, t: Transcript) -> bool:
    bind_budget(t, B, "exact")
    base1, point1, base2, point2 = _budget_dleq_instance(c1_sum, c2_sum, mpk, B)
    return verify_dleq(base1, point1, base2, point2, e, z, t)


def prove_budget_at_most(c1_sum, c2_sum, mpk, B: int, r_sum: int, v_sum: int, t: Transcript, *,
                         w=None, simulated=None) -> list[ORBranch]:
    """``atMost`` budget: OR over ``{0..B}`` that the sum encrypts ``v_sum <= B``."""
    bind_budget(t, B, "atMost")
    candidates = list(range(B + 1))
    return prove_or(c1_sum, c2_sum, mpk, candidates, r_sum, v_sum, t, w=w, simulated=simulated)


def verify_budget_at_most(c1_sum, c2_sum, mpk, B: int, branches, t: Transcript) -> bool:
    bind_budget(t, B, "atMost")
    candidates = list(range(B + 1))
    return verify_or(c1_sum, c2_sum, mpk, candidates, branches, t)
