"""ATTESTATION_V1 sign/verify, weight binding, and the normative port verifier."""

from __future__ import annotations

from geg.crypto import attestation, schnorr
from geg.crypto.points import g1_to_compressed
from geg.envelopes.types import Attestation, AttestationScheme
from geg.ports.eligibility import verify_attestation

ELECTION = b"\x11" * 32
PSEUDO = b"\x22" * 32


def _elig_key():
    sk, vk = schnorr.keygen()
    return sk, vk, g1_to_compressed(vk)


def _voter_vk():
    _, vk = schnorr.keygen()
    return g1_to_compressed(vk)


def _attest(sk, vk, vk_bytes, weight, election=ELECTION, pseudo=PSEUDO, nonce=1):
    sig = attestation.sign_attestation(sk, vk, election, pseudo, vk_bytes, weight, nonce)
    return Attestation(election_id=election, pseudonym=pseudo, vk=vk_bytes, weight=weight,
                       signature=sig, nonce=nonce)


def test_sign_then_verify_ok():
    sk, vk, vk_b = _elig_key()
    voter = _voter_vk()
    att = _attest(sk, vk, voter, weight=7)
    assert verify_attestation(vk_b, att, election_id=ELECTION)


def test_weight_1_ok():
    sk, vk, vk_b = _elig_key()
    att = _attest(sk, vk, _voter_vk(), weight=1)
    assert verify_attestation(vk_b, att, election_id=ELECTION)


def test_accepts_a_large_weight():
    """No upper bound survives: the per-election ceiling is gone.

    It only made sense while voting power was clamped — once it is not, the bound has
    to sit at or above the largest legitimate holder, at which point it constrains
    nothing an attacker would want. Weights ride in the clear inside every ballot, so
    a forged one is visible to an auditor rather than merely blocked.
    """
    sk, vk, vk_b = _elig_key()
    att = _attest(sk, vk, _voter_vk(), weight=10**9)
    assert verify_attestation(vk_b, att, election_id=ELECTION)


def test_rejects_wrong_election_binding():
    sk, vk, vk_b = _elig_key()
    att = _attest(sk, vk, _voter_vk(), weight=3)
    assert not verify_attestation(vk_b, att, election_id=b"\x99" * 32)


def test_rejects_tampered_weight():
    """Signature covers weight; changing the envelope weight must fail."""
    sk, vk, vk_b = _elig_key()
    att = _attest(sk, vk, _voter_vk(), weight=3)
    tampered = Attestation(
        election_id=att.election_id, pseudonym=att.pseudonym, vk=att.vk,
        weight=9, signature=att.signature,
    )
    assert not verify_attestation(vk_b, tampered, election_id=ELECTION)


def test_rejects_tampered_nonce():
    """Signature covers the re-vote nonce; changing the envelope nonce must fail (this is
    what stops a replayed old ballot from masquerading as a newer one)."""
    sk, vk, vk_b = _elig_key()
    att = _attest(sk, vk, _voter_vk(), weight=3, nonce=1)
    tampered = Attestation(
        election_id=att.election_id, pseudonym=att.pseudonym, vk=att.vk,
        weight=att.weight, signature=att.signature, nonce=2,
    )
    assert not verify_attestation(vk_b, tampered, election_id=ELECTION)


def test_nonce_changes_message():
    """Distinct nonces yield distinct signed messages (so a higher-nonce credential is a
    genuinely different signature, not derivable from a lower one)."""
    voter = _voter_vk()
    assert (attestation.attestation_message(ELECTION, PSEUDO, voter, weight=1, nonce=1)
            != attestation.attestation_message(ELECTION, PSEUDO, voter, weight=1, nonce=2))


def test_rejects_wrong_eligibility_key():
    sk, vk, _ = _elig_key()
    _, _, other_vk_b = _elig_key()
    att = _attest(sk, vk, _voter_vk(), weight=3)
    assert not verify_attestation(other_vk_b, att, election_id=ELECTION)


def test_rejects_tampered_signature():
    sk, vk, vk_b = _elig_key()
    att = _attest(sk, vk, _voter_vk(), weight=3)
    sig = bytearray(att.signature)
    sig[-1] ^= 0x01
    tampered = Attestation(
        election_id=att.election_id, pseudonym=att.pseudonym, vk=att.vk,
        weight=att.weight, signature=bytes(sig),
    )
    assert not verify_attestation(vk_b, tampered, election_id=ELECTION)


def test_distinct_from_legacy_scheme():
    """ATTESTATION_V1 is domain-separated + weighted, so its message differs from
    the legacy keccak(electionId||pseudonym||vk) concatenation."""
    from eth_utils import keccak
    voter = _voter_vk()
    legacy = keccak(ELECTION + PSEUDO + voter)
    v1 = attestation.attestation_message(ELECTION, PSEUDO, voter, weight=1, nonce=1)
    assert legacy != v1
