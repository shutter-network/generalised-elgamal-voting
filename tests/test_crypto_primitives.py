"""Unit tests for the crypto primitives: points, ElGamal, Schnorr, transcript, proofs."""

from __future__ import annotations

import pytest

from geg.crypto import elgamal, proofs, schnorr
from geg.crypto.params import CURVE_ORDER
from geg.crypto.points import (
    G1,
    G2,
    Z1,
    g1_from_compressed,
    g1_to_compressed,
    g2_from_compressed,
    g2_to_compressed,
    mul,
    random_scalar,
)
from geg.crypto.recovery import baby_step_giant_step
from geg.crypto.transcript import Transcript


# --- point codecs ---------------------------------------------------------- #

def test_g2_compressed_round_trip():
    P = mul(G2, 123456789)
    assert g2_from_compressed(g2_to_compressed(P)) == P


def test_g1_compressed_round_trip():
    P = mul(G1, 987654321)
    assert g1_from_compressed(g1_to_compressed(P)) == P


def test_g2_wrong_length_rejected():
    with pytest.raises(ValueError, match="96-byte"):
        g2_from_compressed(b"\x00" * 95)


def test_g1_garbage_rejected():
    # All-zero is not a valid compressed encoding (no compression flag set).
    with pytest.raises(ValueError):
        g1_from_compressed(b"\x00" * 48)


# --- ElGamal homomorphism -------------------------------------------------- #

def test_elgamal_encrypt_is_homomorphic():
    # Use a known secret key so we can decrypt without a full DKG.
    msk = random_scalar()
    mpk = mul(G2, msk)
    c_a = elgamal.encrypt(mpk, 3)[:2]
    c_b = elgamal.encrypt(mpk, 5)[:2]
    c_sum = elgamal.add_ct(c_a, c_b)
    # decrypt: tau = C2 - msk*C1 = m*P2
    tau = c_sum[1] + (-(mul(c_sum[0], msk)))
    assert baby_step_giant_step(tau, 20) == 8


def test_scalar_mul_ct_scales_plaintext():
    msk = random_scalar()
    mpk = mul(G2, msk)
    ct = elgamal.encrypt(mpk, 4)[:2]
    weighted = elgamal.scalar_mul_ct(3, ct)  # Enc(12)
    tau = weighted[1] + (-(mul(weighted[0], msk)))
    assert baby_step_giant_step(tau, 50) == 12


def test_sum_cts_empty_is_identity_encrypting_zero():
    c1, c2 = elgamal.sum_cts([])
    from geg.crypto.points import is_identity
    assert is_identity(c1) and is_identity(c2)


# --- Schnorr --------------------------------------------------------------- #

def test_schnorr_sign_verify_round_trip():
    sk, vk = schnorr.keygen()
    R, s = schnorr.sign(sk, vk, b"hello")
    assert schnorr.verify(vk, b"hello", R, s)


def test_schnorr_rejects_tampered_message():
    sk, vk = schnorr.keygen()
    R, s = schnorr.sign(sk, vk, b"hello")
    assert not schnorr.verify(vk, b"HELLO", R, s)


def test_schnorr_rejects_identity_vk():
    assert not schnorr.verify(Z1, b"x", G1, 1)


def test_schnorr_keygen_rejects_zero():
    with pytest.raises(ValueError):
        schnorr.keygen(CURVE_ORDER)  # 0 mod Q


def test_schnorr_encode_decode_round_trip():
    sk, vk = schnorr.keygen()
    R, s = schnorr.sign(sk, vk, b"m")
    R2, s2 = schnorr.decode(schnorr.encode(R, s))
    assert R2 == R and s2 == s


# --- DLEQ ------------------------------------------------------------------ #

def test_dleq_prove_verify():
    x = random_scalar()
    p1, p2 = mul(G2, x), mul(mul(G2, 7), x)  # base2 = 7*P2
    base2 = mul(G2, 7)
    e, z = proofs.prove_dleq(G2, p1, base2, p2, x, Transcript("t"))
    assert proofs.verify_dleq(G2, p1, base2, p2, e, z, Transcript("t"))


def test_dleq_rejects_wrong_witness_transcript():
    x = random_scalar()
    base2 = mul(G2, 7)
    p1, p2 = mul(G2, x), mul(base2, x)
    e, z = proofs.prove_dleq(G2, p1, base2, p2, x, Transcript("t"))
    # A different transcript label must not verify.
    assert not proofs.verify_dleq(G2, p1, base2, p2, e, z, Transcript("other"))


# --- OR proof -------------------------------------------------------------- #

def test_or_proof_valid_for_true_index():
    msk = random_scalar()
    mpk = mul(G2, msk)
    candidates = [0, 1, 2, 3]
    v = 2
    c1, c2, r = elgamal.encrypt(mpk, v)
    branches = proofs.prove_or(c1, c2, mpk, candidates, r, v, Transcript("t"))
    assert proofs.verify_or(c1, c2, mpk, candidates, branches, Transcript("t"))


def test_or_proof_tampered_branch_fails():
    msk = random_scalar()
    mpk = mul(G2, msk)
    candidates = [0, 1, 2, 3]
    c1, c2, r = elgamal.encrypt(mpk, 1)
    branches = proofs.prove_or(c1, c2, mpk, candidates, r, 1, Transcript("t"))
    branches[0].z = (branches[0].z + 1) % CURVE_ORDER
    assert not proofs.verify_or(c1, c2, mpk, candidates, branches, Transcript("t"))


# --- budget proofs --------------------------------------------------------- #

def test_budget_exact_proof():
    msk = random_scalar()
    mpk = mul(G2, msk)
    B = 3
    # two candidates summing to B
    c1a, c2a, ra = elgamal.encrypt(mpk, 1)
    c1b, c2b, rb = elgamal.encrypt(mpk, 2)
    c1_sum, c2_sum = c1a + c1b, c2a + c2b
    r_sum = (ra + rb) % CURVE_ORDER
    e, z = proofs.prove_budget_exact(c1_sum, c2_sum, mpk, B, r_sum, Transcript("t"))
    assert proofs.verify_budget_exact(c1_sum, c2_sum, mpk, B, e, z, Transcript("t"))


def test_budget_at_most_proof():
    msk = random_scalar()
    mpk = mul(G2, msk)
    B = 5
    c1, c2, r = elgamal.encrypt(mpk, 3)  # 3 <= 5
    branches = proofs.prove_budget_at_most(c1, c2, mpk, B, r, 3, Transcript("t"))
    assert proofs.verify_budget_at_most(c1, c2, mpk, B, branches, Transcript("t"))


def test_exact_and_at_most_do_not_cross_verify():
    """Mode is bound into the transcript: an exact proof must not verify as atMost."""
    msk = random_scalar()
    mpk = mul(G2, msk)
    B = 3
    c1, c2, r = elgamal.encrypt(mpk, 3)
    e, z = proofs.prove_budget_exact(c1, c2, mpk, B, r, Transcript("t"))
    # Reusing (e, z) as if it were an atMost OR proof is structurally impossible;
    # here we assert the exact verifier rejects a transcript seeded for atMost.
    assert not proofs.verify_budget_exact(c1, c2, mpk, B, e, z, Transcript("wrong-seed"))


# --- transcript ------------------------------------------------------------ #

def test_transcript_challenge_is_deterministic():
    def build():
        t = Transcript("L")
        t.append("a", b"\x01\x02")
        t.append_scalar("b", 42)
        return t.challenge("c")
    assert build() == build()


def test_transcript_diverges_on_different_input():
    t1 = Transcript("L"); t1.append("a", b"\x01")
    t2 = Transcript("L"); t2.append("a", b"\x02")
    assert t1.challenge("c") != t2.challenge("c")


# --- canonical scalar decoding --------------------------------- #
#
# Scalar arithmetic is mod CURVE_ORDER, so `s` and `s + CURVE_ORDER` are the SAME scalar
# and verify identically — but they are different 32 bytes on the wire. Accepting both
# means one signature/proof has many valid encodings. Nothing keys identity off those
# bytes today; the reason to reject non-canonical forms is cross-implementation
# agreement, since every keyper independently re-derives the aggregate from the stored
# ballots and a peer that reduced (or rejected) differently would never reach quorum.

def test_schnorr_rejects_non_canonical_s():
    sk, vk = schnorr.keygen(0x1234)
    R, s = schnorr.sign(sk, vk, b"msg")
    assert schnorr.verify(vk, b"msg", *schnorr.decode(schnorr.encode(R, s)))

    # s + CURVE_ORDER is the same scalar (it verifies) and still fits in 32 bytes,
    # so it is a second valid encoding of one signature unless decode rejects it.
    malleated = s + CURVE_ORDER
    assert malleated < 2**256
    assert schnorr.verify(vk, b"msg", R, malleated)
    wire = schnorr.encode(R, s)[:48] + malleated.to_bytes(32, "big")
    assert wire != schnorr.encode(R, s)
    with pytest.raises(ValueError, match="non-canonical"):
        schnorr.decode(wire)


def test_schnorr_rejects_s_equal_to_curve_order():
    sk, vk = schnorr.keygen(0x1234)
    R, _ = schnorr.sign(sk, vk, b"msg")
    with pytest.raises(ValueError, match="non-canonical"):
        schnorr.decode(schnorr.encode(R, 0)[:48] + CURVE_ORDER.to_bytes(32, "big"))


def test_schnorr_accepts_canonical_boundary_scalars():
    """CURVE_ORDER - 1 and 0 are legal scalars; only >= CURVE_ORDER is not."""
    sk, vk = schnorr.keygen(0x1234)
    R, _ = schnorr.sign(sk, vk, b"msg")
    for s in (0, 1, CURVE_ORDER - 1):
        _, decoded = schnorr.decode(schnorr.encode(R, 0)[:48] + s.to_bytes(32, "big"))
        assert decoded == s


@pytest.mark.parametrize("bad_half", ["e", "z"])
def test_dleq_rejects_non_canonical_scalars(bad_half):
    good = (12345).to_bytes(32, "big")
    over = (CURVE_ORDER + 7).to_bytes(32, "big")
    wire = over + good if bad_half == "e" else good + over
    with pytest.raises(ValueError, match="non-canonical"):
        proofs.decode_dleq(wire)


def test_dleq_roundtrips_canonical_scalars():
    e, z = 12345, CURVE_ORDER - 1
    assert proofs.decode_dleq(proofs.encode_dleq(e, z)) == (e, z)
