"""Stub eligibility adapter: issued attestations verify under the normative path."""

from __future__ import annotations

from geg.adapters.eligibility_stub import StubEligibilityService
from geg.crypto import schnorr
from geg.crypto.points import g1_to_compressed
from geg.envelopes.types import AttestationScheme
from geg.ports.eligibility import AttestationRequest, verify_attestation

ELECTION = b"\x11" * 32
PSEUDO = b"\x22" * 32


def _voter_vk() -> bytes:
    _, vk = schnorr.keygen()
    return g1_to_compressed(vk)


def _request(weight: int = 1) -> AttestationRequest:
    return AttestationRequest(election_id=ELECTION, pseudonym=PSEUDO, vk=_voter_vk(), weight=weight)


def test_issued_v1_attestation_verifies():
    elig_sk, _ = schnorr.keygen()
    svc = StubEligibilityService(elig_sk)
    att = svc.issue_attestation(_request(weight=5))
    assert att.scheme is AttestationScheme.V1 and att.weight == 5
    assert verify_attestation(svc.eligibility_key, att, election_id=ELECTION)


def test_fixed_weight_override():
    elig_sk, _ = schnorr.keygen()
    svc = StubEligibilityService(elig_sk, fixed_weight=1)
    att = svc.issue_attestation(_request(weight=9))  # request asks 9, stub pins 1
    assert att.weight == 1
    assert verify_attestation(svc.eligibility_key, att, election_id=ELECTION)


def test_issued_legacy_attestation_verifies_at_weight_1():
    elig_sk, _ = schnorr.keygen()
    svc = StubEligibilityService(elig_sk, scheme=AttestationScheme.LEGACY)
    att = svc.issue_attestation(_request(weight=7))  # legacy forces weight 1
    assert att.scheme is AttestationScheme.LEGACY and att.weight == 1
    assert verify_attestation(svc.eligibility_key, att, election_id=ELECTION)


def test_verification_is_adapter_independent():
    """Same voter tuple, two stub instances with the same key → interchangeable."""
    elig_sk, _ = schnorr.keygen()
    a = StubEligibilityService(elig_sk)
    b = StubEligibilityService(elig_sk)
    assert a.eligibility_key == b.eligibility_key
    req = _request(weight=3)
    att = a.issue_attestation(req)
    assert verify_attestation(b.eligibility_key, att, election_id=ELECTION)
