"""Wallet-authenticated eligibility service (chain-free EIP-191 personal-sign): an
attestation issued for a wallet-signed challenge verifies under the normative
``verify_attestation``; the pseudonym is stable per (wallet, election) so re-votes dedupe;
and a missing/invalid signature is rejected."""

from __future__ import annotations

import json

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


def _allow_client(tmp_path, mapping, weight=3):
    """A test client whose issuance is gated by an ``ELIGIBILITY_ALLOWLIST`` file holding
    ``mapping`` (object or array). Returns (client, path) so the file can be re-edited."""
    p = tmp_path / "allow.json"
    p.write_text(json.dumps(mapping))
    svc = StubEligibilityService(ELIG_SK)
    app = build_eligibility_app(svc, pseudonym_secret=SECRET, weight=weight, allowlist_path=str(p))
    return app.test_client(), p


def test_allowlist_denies_unlisted_wallet(tmp_path):
    c, _ = _allow_client(tmp_path, {"0x" + "11" * 20: 1})
    r = _post(c, Account.create(), EID, _vk())
    assert r.status_code == 403, r.get_json()
    assert "eligible" in r.get_json()["message"].lower()


def test_allowlist_allows_listed_wallet_with_its_weight(tmp_path):
    acct = Account.create()  # checksummed address; the allowlist is case-insensitive
    c, _ = _allow_client(tmp_path, {acct.address: 5}, weight=1)
    r = _post(c, acct, EID, _vk())
    assert r.status_code == 200, r.get_json()
    assert codecs.dec_attestation(r.get_json()["attestation"]).weight == 5


def test_allowlist_array_form_uses_default_weight(tmp_path):
    acct = Account.create()
    c, _ = _allow_client(tmp_path, [acct.address], weight=2)
    r = _post(c, acct, EID, _vk())
    assert r.status_code == 200, r.get_json()
    assert codecs.dec_attestation(r.get_json()["attestation"]).weight == 2


def test_allowlist_hot_reload_takes_effect_without_restart(tmp_path):
    acct = Account.create()
    c, p = _allow_client(tmp_path, {"0x" + "11" * 20: 1})
    assert _post(c, acct, EID, _vk()).status_code == 403  # not listed yet
    p.write_text(json.dumps({acct.address: 1}))            # edit the file mid-flight
    assert _post(c, acct, EID, _vk()).status_code == 200   # now eligible, no restart


def test_allowlist_malformed_file_is_server_error(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("this is not json")
    svc = StubEligibilityService(ELIG_SK)
    c = build_eligibility_app(svc, pseudonym_secret=SECRET, allowlist_path=str(p)).test_client()
    r = _post(c, Account.create(), EID, _vk())
    assert r.status_code == 500, r.get_json()


def test_nonce_increments_per_wallet_and_election():
    """Each /attest for the same (election, wallet) gets a strictly higher nonce (re-vote
    counter); a different wallet or election starts its own sequence at 1."""
    c = _client()
    a1, a2 = Account.create(), Account.create()

    def nonce(acct, eid):
        r = _post(c, acct, eid, _vk())
        assert r.status_code == 200, r.get_json()
        return codecs.dec_attestation(r.get_json()["attestation"]).nonce

    assert nonce(a1, EID) == 1          # first vote
    assert nonce(a1, EID) == 2          # re-vote → higher
    assert nonce(a1, EID) == 3          # again
    assert nonce(a2, EID) == 1          # a different wallet starts fresh
    other_eid = (2).to_bytes(32, "big")
    assert nonce(a1, other_eid) == 1    # same wallet, different election starts fresh


def test_revote_attestation_verifies_with_its_nonce():
    """A re-vote's attestation (nonce 2) verifies under the normative verifier — proving the
    issuer signs the bound nonce, so the tally can trust the ordering."""
    from geg.ports.eligibility import verify_attestation
    c = _client(weight=1)
    acct = Account.create()
    _post(c, acct, EID, _vk())               # nonce 1
    r = _post(c, acct, EID, _vk())           # nonce 2
    att = codecs.dec_attestation(r.get_json()["attestation"])
    assert att.nonce == 2
    elig_key = StubEligibilityService(ELIG_SK).eligibility_key
    assert verify_attestation(elig_key, att, election_id=EID, max_weight=10)


def test_sqlite_nonce_store_is_monotonic_and_durable(tmp_path):
    """The durable store hands out 1,2,3… per (election, pseudonym) and survives reopen
    (so a restart cannot regress a voter's nonce and let a stale ballot win)."""
    from geg.services.eligibility.eligibility import SqliteNonceStore
    path = str(tmp_path / "nonces.db")
    store = SqliteNonceStore(path)
    assert store.next(EID, b"\x01" * 32) == 1
    assert store.next(EID, b"\x01" * 32) == 2
    assert store.next(EID, b"\x02" * 32) == 1  # different pseudonym, own sequence
    reopened = SqliteNonceStore(path)          # simulate a restart
    assert reopened.next(EID, b"\x01" * 32) == 3


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

# --------------------------------------------------------------------------- #
#  max_weight clamp
# --------------------------------------------------------------------------- #

EID_2 = (2).to_bytes(32, "big")


def _clamping_client(weight, caps: dict):
    """An issuer whose cap comes from a per-election lookup, as `main()` wires it."""
    svc = StubEligibilityService(ELIG_SK)
    return build_eligibility_app(
        svc, pseudonym_secret=SECRET, weight=weight,
        max_weight_for=lambda eid: caps[bytes(eid)],
    ).test_client()


def _issued_weight(resp) -> int:
    return codecs.dec_attestation(resp.get_json()["attestation"]).weight


def test_weight_is_clamped_to_the_election_max():
    """Over-weight credentials are unusable: verify_attestation rejects weight > max_weight
    at tally, so issuing one hands the voter something the ingest filter turns away as
    INVALID_ATTESTATION (or, with the filter off, is dropped silently at the tally)."""
    c = _clamping_client(weight=79, caps={EID: 50})
    r = _post(c, Account.create(), EID, _vk())
    assert r.status_code == 200
    assert _issued_weight(r) == 50


def test_weight_below_the_cap_is_untouched():
    c = _clamping_client(weight=79, caps={EID: 100})
    r = _post(c, Account.create(), EID, _vk())
    assert _issued_weight(r) == 79


def test_the_cap_is_per_election_not_global():
    """The same voter legitimately gets different weights in different elections: power 79
    is clamped to 50 under an election capped at 50, but stands at 79 under one capped at
    100. A single global cap (an env var, or an adapter-constructor value) would be wrong."""
    c = _clamping_client(weight=79, caps={EID: 50, EID_2: 100})
    acct = Account.create()
    assert _issued_weight(_post(c, acct, EID, _vk())) == 50
    assert _issued_weight(_post(c, acct, EID_2, _vk())) == 79


def test_unavailable_max_weight_fails_closed():
    """If the election's cap cannot be read, refuse to issue. An unclamped credential is
    unusable at tally anyway, so issuing one only moves the failure somewhere confusing."""
    def _boom(_eid):
        raise RuntimeError("api unreachable")

    svc = StubEligibilityService(ELIG_SK)
    c = build_eligibility_app(svc, pseudonym_secret=SECRET, weight=5, max_weight_for=_boom).test_client()
    r = _post(c, Account.create(), EID, _vk())
    assert r.status_code == 503
    assert "weight limit" in r.get_json()["message"]


def test_allowlist_weight_is_clamped_too(tmp_path):
    """The allowlist is the other unbounded source: `load_allowlist` does int(w) with no
    upper bound, so a mis-set entry would otherwise mint an unusable credential."""
    acct = Account.create()
    p = tmp_path / "allow.json"
    p.write_text(json.dumps({acct.address: 999}))
    svc = StubEligibilityService(ELIG_SK)
    c = build_eligibility_app(svc, pseudonym_secret=SECRET, weight=1, allowlist_path=str(p),
                              max_weight_for=lambda _eid: 10).test_client()
    assert _issued_weight(_post(c, acct, EID, _vk())) == 10
