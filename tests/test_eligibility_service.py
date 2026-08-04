"""Wallet-authenticated eligibility service (chain-free EIP-191 personal-sign): an
attestation issued for a wallet-signed challenge verifies under the normative
``verify_attestation``; the pseudonym is stable per (wallet, election) so re-votes dedupe;
and a missing/invalid signature is rejected."""

from __future__ import annotations

from eth_account import Account
from eth_account.messages import encode_defunct

from geg.adapters.eligibility_stub import StubEligibilityService
from geg.crypto import schnorr
from geg.crypto.points import g1_to_compressed
from geg.envelopes import codecs
from geg.ports.eligibility import verify_attestation
from geg.services.eligibility.eligibility import build_eligibility_app, challenge_message

ELIG_SK = 0x5772000000000000000000000000000000000000000000000000000000000001
SECRET = b"\xab" * 32
EID = (1).to_bytes(32, "big")


def _client(weight=3):
    svc = StubEligibilityService(ELIG_SK)
    return build_eligibility_app(svc, pseudonym_secret=SECRET, weight=weight).test_client()


def _vk() -> bytes:
    return g1_to_compressed(schnorr.keygen()[1])


def _sign(acct, eid: bytes, vk: bytes) -> str:
    sig = acct.sign_message(encode_defunct(text=challenge_message(eid, vk))).signature
    return codecs.enc_bytes(sig)


def _post(c, acct, eid, vk):
    return c.post("/attest", json={
        "electionId": codecs.enc_bytes(eid), "vk": codecs.enc_bytes(vk),
        "signature": _sign(acct, eid, vk),
    })


def test_attest_roundtrips_and_verifies():
    c = _client(weight=3)
    r = _post(c, Account.create(), EID, _vk())
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    att = codecs.dec_attestation(body["attestation"])
    assert att.weight == 3
    elig_key = StubEligibilityService(ELIG_SK).eligibility_key
    assert verify_attestation(elig_key, att, election_id=EID, max_weight=10)
    assert codecs.dec_bytes(body["pseudonym"], name="pseudonym") == att.pseudonym


def test_same_wallet_same_pseudonym_different_wallet_differs():
    c = _client()
    a1, a2 = Account.create(), Account.create()

    def pseudonym(acct, vk):
        r = _post(c, acct, EID, vk)
        assert r.status_code == 200, r.get_json()
        return r.get_json()["pseudonym"]

    # same wallet, different ballot key (a re-vote) → SAME pseudonym → tally dedups
    assert pseudonym(a1, _vk()) == pseudonym(a1, _vk())
    # different wallet → different pseudonym
    assert pseudonym(a1, _vk()) != pseudonym(a2, _vk())


def test_missing_signature_rejected():
    r = _client().post("/attest", json={
        "electionId": codecs.enc_bytes(EID), "vk": codecs.enc_bytes(_vk())})
    assert r.status_code == 401


def test_bad_signature_rejected():
    r = _client().post("/attest", json={
        "electionId": codecs.enc_bytes(EID), "vk": codecs.enc_bytes(_vk()),
        "signature": codecs.enc_bytes(b"\x00" * 65)})
    assert r.status_code == 401


def test_health_exposes_eligibility_key():
    r = _client().get("/health")
    assert r.status_code == 200
    assert r.get_json()["eligibilityKey"] == codecs.enc_bytes(StubEligibilityService(ELIG_SK).eligibility_key)


def test_cors_headers_present():
    r = _client().get("/health")
    assert r.headers["Access-Control-Allow-Origin"] == "*"


def test_challenge_message_fixture():
    """Cross-impl lock: a fixed key's signature over the canonical challenge recovers a
    known address. The JS voter (viem ``recoverMessageAddress``) recovers the same address
    from the same signature — see the voter app's ``eligibilitySign.test.ts``. If the
    message bytes drift on either side, recovery fails and both break."""
    eid = (1).to_bytes(32, "big")
    vk = bytes.fromhex("ab" * 48)
    sig = bytes.fromhex(
        "6095900a3840d0fb149f73cda9d07944005415ae6ba6cc0fd035030357e16a87"
        "5e4fd6d174cb3f47b61c15f04107d5eb020d04bc9b5be8e2cb1166406a49f1c61c")
    recovered = Account.recover_message(
        encode_defunct(text=challenge_message(eid, vk)), signature=sig)
    assert recovered == "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"