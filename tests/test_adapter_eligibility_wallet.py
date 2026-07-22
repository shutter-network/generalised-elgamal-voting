"""Wallet eligibility adapter: EIP-712 challenge, voting-power weight, pseudonyms."""

from __future__ import annotations

import pytest
from eth_account import Account
from eth_utils import keccak

from geg.adapters.eligibility_wallet import (
    EligibilityError,
    NotEligible,
    WalletAttestationRequest,
    WalletEligibilityService,
)
from geg.crypto import schnorr
from geg.crypto.points import g1_to_compressed
from geg.ports.eligibility import verify_attestation

from conftest import ELECTION_ID as ELECTION  # keep in sync with env.config()'s id
CHAIN_ID = 100


def _voter():
    acct = Account.create()
    return acct, bytes.fromhex(acct.address[2:])


def _vk():
    _, vk = schnorr.keygen()
    return g1_to_compressed(vk)


def _service(vp_map, max_weight=10):
    elig_sk, _ = schnorr.keygen()
    return WalletEligibilityService(
        elig_sk, lambda a: vp_map.get(a, 0), max_weight=max_weight, chain_id=CHAIN_ID
    )


def _sign(svc, acct, election_id, vk_bytes):
    return acct.sign_message(svc.challenge(election_id, vk_bytes)).signature


def test_issue_and_verify_with_voting_power_weight():
    acct, addr = _voter()
    svc = _service({addr: 4})
    vk = _vk()
    att = svc.issue_for_wallet(ELECTION, vk, _sign(svc, acct, ELECTION, vk))
    assert att.weight == 4
    assert att.pseudonym == keccak(addr + ELECTION)
    assert verify_attestation(svc.eligibility_key, att, election_id=ELECTION, max_weight=10)


def test_voting_power_clamped_to_max_weight():
    acct, addr = _voter()
    svc = _service({addr: 1_000_000}, max_weight=10)
    vk = _vk()
    att = svc.issue_for_wallet(ELECTION, vk, _sign(svc, acct, ELECTION, vk))
    assert att.weight == 10  # clamped
    assert verify_attestation(svc.eligibility_key, att, election_id=ELECTION, max_weight=10)


def test_zero_voting_power_rejected():
    acct, addr = _voter()
    svc = _service({})  # no power
    vk = _vk()
    with pytest.raises(NotEligible):
        svc.issue_for_wallet(ELECTION, vk, _sign(svc, acct, ELECTION, vk))


def test_malformed_signature_rejected():
    _, addr = _voter()
    svc = _service({addr: 3})
    with pytest.raises(EligibilityError):
        svc.issue_for_wallet(ELECTION, _vk(), b"\x00" * 65)


def test_signature_replayed_to_other_election_rejected():
    """A challenge signed for one election recovers a different address elsewhere."""
    acct, addr = _voter()
    svc = _service({addr: 3})
    vk = _vk()
    sig = _sign(svc, acct, ELECTION, vk)  # signed for ELECTION
    other = b"\x99" * 32
    with pytest.raises(NotEligible):  # recovered addr for `other` has no power
        svc.issue_for_wallet(other, vk, sig)


def test_signature_not_transferable_to_other_vk():
    acct, addr = _voter()
    svc = _service({addr: 3})
    vk1, vk2 = _vk(), _vk()
    sig = _sign(svc, acct, ELECTION, vk1)  # bound to vk1
    with pytest.raises(NotEligible):  # recovered addr for vk2 differs → no power
        svc.issue_for_wallet(ELECTION, vk2, sig)


def test_pseudonym_unlinkable_across_elections():
    acct, addr = _voter()
    svc = _service({addr: 3})
    vk = _vk()
    a1 = svc.issue_for_wallet(ELECTION, vk, _sign(svc, acct, ELECTION, vk))
    e2 = b"\x22" * 32
    a2 = svc.issue_for_wallet(e2, vk, _sign(svc, acct, e2, vk))
    assert a1.pseudonym != a2.pseudonym  # unlinkable across elections


def test_double_issuance_prevented():
    acct, addr = _voter()
    svc = _service({addr: 3})
    vk = _vk()
    sig = _sign(svc, acct, ELECTION, vk)
    svc.issue_for_wallet(ELECTION, vk, sig)
    with pytest.raises(EligibilityError):
        svc.issue_for_wallet(ELECTION, vk, sig)


def test_issue_attestation_requires_wallet_request():
    from geg.ports.eligibility import AttestationRequest

    _, addr = _voter()
    svc = _service({addr: 3})
    with pytest.raises(EligibilityError):
        svc.issue_attestation(AttestationRequest(ELECTION, b"\x00" * 32, _vk(), 1))


def test_issue_attestation_via_wallet_request():
    acct, addr = _voter()
    svc = _service({addr: 7})
    vk = _vk()
    req = WalletAttestationRequest(ELECTION, vk, _sign(svc, acct, ELECTION, vk))
    att = svc.issue_attestation(req)
    assert att.weight == 7


def test_wallet_attestation_flows_through_admission(env):
    """A wallet-issued credential drives a real weighted admission end-to-end."""
    from geg.core.admission import StoredBallot, admit
    from geg.crypto import ballot as ballot_crypto
    from geg.envelopes.types import BallotEnvelope, Ciphertext

    acct, addr = _voter()
    svc = _service({addr: 3}, max_weight=10)
    sk, vk = schnorr.keygen()
    vk_bytes = g1_to_compressed(vk)
    att = svc.issue_for_wallet(ELECTION, vk_bytes, _sign(svc, acct, ELECTION, vk_bytes))

    built = ballot_crypto.build_ballot(
        mpk=env.mpk_point, election_id=ELECTION, pseudonym=att.pseudonym,
        sk=sk, vk=vk, votes=[1, 0, 2], num_candidates=3, budget=3,
    )
    envelope = BallotEnvelope(
        election_id=ELECTION, pseudonym=att.pseudonym, vk=vk_bytes,
        ciphertexts=tuple(Ciphertext(c1=a, c2=b) for (a, b) in built.ciphertexts),
        zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att,
    )
    cfg = env.config(eligibility_key=svc.eligibility_key, weighted=True, max_weight=10)
    result = admit([StoredBallot(0, envelope)], cfg, env.mpk_bytes)
    assert len(result.admitted) == 1
    assert result.admitted[0].weight == 3
    assert result.total_admitted_weight == 3
