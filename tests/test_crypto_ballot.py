"""Ballot construction + crypto verification (Variant A / exact)."""

from __future__ import annotations

import pytest

from geg.crypto import ballot, schnorr
from geg.crypto.points import G2, mul, random_scalar


def _mpk():
    return mul(G2, random_scalar())


def _build(votes, budget, mpk=None, election_id=None, pseudonym=None):
    mpk = mpk or _mpk()
    sk, vk = schnorr.keygen()
    return mpk, ballot.build_ballot(
        mpk=mpk,
        election_id=election_id or b"\x11" * 32,
        pseudonym=pseudonym or b"\x22" * 32,
        sk=sk, vk=vk,
        votes=votes,
        num_candidates=len(votes),
        budget=budget,
    )


def _verify(mpk, b, num_candidates, budget):
    return ballot.verify_ballot_crypto(
        mpk=mpk,
        election_id=b.election_id,
        pseudonym=b.pseudonym,
        vk_bytes=b.vk,
        ciphertext_bytes=b.ciphertexts,
        zk_proof=b.zk_proof,
        voter_signature=b.voter_signature,
        num_candidates=num_candidates,
        budget=budget,
    )


def test_build_then_verify_ok():
    mpk, b = _build([1, 0, 2], budget=3)
    ok, reason = _verify(mpk, b, 3, 3)
    assert ok and reason is None


def test_single_choice_budget_1():
    mpk, b = _build([0, 1], budget=1)
    ok, reason = _verify(mpk, b, 2, 1)
    assert ok and reason is None


def test_build_rejects_wrong_sum_exact():
    with pytest.raises(ValueError, match="exact mode requires"):
        _build([1, 1, 0], budget=3)  # sum 2 != 3


def test_build_rejects_out_of_range_vote():
    with pytest.raises(ValueError, match="not in"):
        _build([5, 0], budget=3)


def test_tampered_ciphertext_fails_proof():
    mpk, b = _build([1, 2], budget=3)
    # Swap in a different valid ciphertext component (breaks the range proof binding).
    other_mpk, other = _build([2, 1], budget=3, mpk=mpk)
    tampered = b.ciphertexts[:]
    tampered[0] = other.ciphertexts[0]
    b.ciphertexts = tampered
    ok, reason = _verify(mpk, b, 2, 3)
    assert not ok and reason in ("INVALID_PROOF", "INVALID_SIGNATURE")


def test_tampered_signature_detected():
    mpk, b = _build([1, 2], budget=3)
    # Corrupt the signature's scalar half.
    sig = bytearray(b.voter_signature)
    sig[-1] ^= 0x01
    b.voter_signature = bytes(sig)
    ok, reason = _verify(mpk, b, 2, 3)
    assert not ok and reason in ("INVALID_SIGNATURE", "MALFORMED")


def test_wrong_mpk_fails():
    mpk, b = _build([1, 2], budget=3)
    ok, reason = _verify(_mpk(), b, 2, 3)  # different mpk
    assert not ok


def test_bvp_codec_round_trip():
    mpk, b = _build([1, 0, 2], budget=3)
    rp, e, z = ballot.decode_ballot_validity_proof(b.zk_proof, 3, 3)
    reencoded = ballot.encode_ballot_validity_proof(rp, e, z)
    assert reencoded == b.zk_proof


def test_bvp_decode_rejects_wrong_params():
    mpk, b = _build([1, 0, 2], budget=3)
    with pytest.raises(ValueError, match="numCandidates|branch_count"):
        ballot.decode_ballot_validity_proof(b.zk_proof, 2, 3)


def test_canonical_message_binds_election_id():
    m1 = ballot.canonical_ballot_message(b"\x11" * 32, b"\x22" * 32, [], b"")
    m2 = ballot.canonical_ballot_message(b"\x33" * 32, b"\x22" * 32, [], b"")
    assert m1 != m2
