"""Ballot Gateway HTTP ingest service: accept valid ballots, reject/filter others.

The filter is non-authoritative: with it off, an invalid ballot
is still accepted (injected) — the tally would exclude it. Uses the in-process
`full_env` (registers + finalizes DKG in-process) with the HTTP gateway over it.
"""

from __future__ import annotations

from dataclasses import replace

from geg.envelopes import codecs
from geg.services import admin
from geg.services.coordinator import dkg_coordinator as coord
from geg.services.api import build_api_app

EID_HEX = (1).to_bytes(32, "big").hex()  # registry-assigned first id


def _ready(fe):
    admin.register_election(fe.dl, fe.config, fe.admin.sign_register(fe.config),
                            admin_identity=fe.admin.identity, clock=fe.clock, dkg_lead_time=0)
    assert coord.ensure_dkg(fe.config.election_id, fe.keypers, fe.dl, n=fe.n, t=fe.t,
                            clock=fe.clock, deadline=fe.config.voting_start)


def test_gateway_accepts_valid_ballot_in_window(full_env):
    fe = full_env
    _ready(fe)
    fe.clock.set(1500)
    client = build_api_app(fe.dl, clock=fe.clock).test_client()
    ballot = codecs.enc_ballot(fe.voter_ballot([3, 0, 0], b"\x01" * 32))
    r = client.post(f"/elections/{EID_HEX}/ballots", json={"ballot": ballot})
    assert r.status_code == 200
    assert r.get_json()["sequenceNumber"] == 0
    assert fe.dl.count_ballots(fe.config.election_id) == 1


def test_gateway_rejects_stale_or_replayed_nonce(full_env):
    """Ingestion replay filter (funds/DoS defense): once a nonce-2 re-vote is stored, a
    ballot with an equal-or-lower nonce for the same pseudonym is rejected before it can
    become a (gas-paying) write. The tally's nonce ordering remains the integrity boundary."""
    fe = full_env
    _ready(fe)
    fe.clock.set(1500)
    client = build_api_app(fe.dl, clock=fe.clock).test_client()
    ps = b"\x01" * 32

    def post(votes, nonce):
        ballot = codecs.enc_ballot(fe.voter_ballot(votes, ps, nonce=nonce))
        return client.post(f"/elections/{EID_HEX}/ballots", json={"ballot": ballot})

    assert post([3, 0, 0], 1).status_code == 200   # first vote
    assert post([0, 3, 0], 2).status_code == 200   # genuine re-vote
    r = post([3, 0, 0], 1)                          # replay of the old (nonce-1) ballot
    assert r.status_code == 400
    assert r.get_json()["reason"] == "STALE_OR_REPLAYED"
    assert fe.dl.count_ballots(fe.config.election_id) == 2  # replay was NOT stored


def test_gateway_rejects_outside_window(full_env):
    fe = full_env
    _ready(fe)
    fe.clock.set(500)  # before voting_start
    client = build_api_app(fe.dl, clock=fe.clock).test_client()
    ballot = codecs.enc_ballot(fe.voter_ballot([3, 0, 0], b"\x01" * 32))
    r = client.post(f"/elections/{EID_HEX}/ballots", json={"ballot": ballot})
    assert r.status_code == 400
    assert r.get_json()["error"] == "REJECTED"


def test_gateway_maps_backend_voting_window_error_to_400(full_env):
    """A lifecycle-enforcing backend (chain) can reject a ballot the gateway's own
    clock thinks is in-window (boundary race). The gateway must surface that backend
    ``VotingWindowError`` as a clean 400, not a 500."""
    from geg.ports.data_layer import VotingWindowError

    fe = full_env
    _ready(fe)
    fe.clock.set(1500)  # gateway's own window check passes (state is Voting)

    def _raise(*_a, **_k):
        raise VotingWindowError("VotingNotStarted(...) at the boundary")

    fe.dl.submit_ballot = _raise  # simulate the chain revert on write
    client = build_api_app(fe.dl, clock=fe.clock).test_client()
    ballot = codecs.enc_ballot(fe.voter_ballot([3, 0, 0], b"\x01" * 32))
    r = client.post(f"/elections/{EID_HEX}/ballots", json={"ballot": ballot})
    assert r.status_code == 400
    assert r.get_json()["error"] == "OUTSIDE_VOTING_WINDOW"


def test_gateway_rejects_malformed(full_env):
    fe = full_env
    _ready(fe)
    fe.clock.set(1500)
    client = build_api_app(fe.dl, clock=fe.clock).test_client()
    r = client.post(f"/elections/{EID_HEX}/ballots", json={"ballot": {"not": "a ballot"}})
    assert r.status_code == 400
    assert r.get_json()["error"] == "MALFORMED"


def test_gateway_filter_off_injects_invalid_ballot(full_env):
    fe = full_env
    _ready(fe)
    fe.clock.set(1500)
    bad = fe.voter_ballot([3, 0, 0], b"\x02" * 32)
    sig = bytearray(bad.voter_signature); sig[-1] ^= 1
    bad = replace(bad, voter_signature=bytes(sig))

    # Filter on → rejected.
    on = build_api_app(fe.dl, clock=fe.clock, filter_on=True).test_client()
    assert on.post(f"/elections/{EID_HEX}/ballots", json={"ballot": codecs.enc_ballot(bad)}).status_code == 400
    # Filter off → accepted (injected); tally-time verification would exclude it.
    off = build_api_app(fe.dl, clock=fe.clock, filter_on=False).test_client()
    assert off.post(f"/elections/{EID_HEX}/ballots", json={"ballot": codecs.enc_ballot(bad)}).status_code == 200
