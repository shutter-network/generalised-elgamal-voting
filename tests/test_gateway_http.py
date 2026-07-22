"""Ballot Gateway HTTP ingest service: accept valid ballots, reject/filter others.

The filter is non-authoritative (DESIGN.md §6.2): with it off, an invalid ballot
is still accepted (injected) — the tally would exclude it. Uses the in-process
`full_env` (registers + finalizes DKG in-process) with the HTTP gateway over it.
"""

from __future__ import annotations

from dataclasses import replace

from geg.envelopes import codecs
from geg.services import admin
from geg.services.coordinator import dkg_coordinator as coord
from geg.services.gateway import build_gateway_app

EID_HEX = (1).to_bytes(32, "big").hex()  # registry-assigned first id


def _ready(fe):
    admin.register_election(fe.dl, fe.config, fe.admin, clock=fe.clock, dkg_lead_time=0)
    assert coord.ensure_dkg(fe.config.election_id, fe.keypers, fe.dl, n=fe.n, t=fe.t,
                            clock=fe.clock, deadline=fe.config.voting_start)


def test_gateway_accepts_valid_ballot_in_window(full_env):
    fe = full_env
    _ready(fe)
    fe.clock.set(1500)
    client = build_gateway_app(fe.dl, clock=fe.clock).test_client()
    ballot = codecs.enc_ballot(fe.voter_ballot([3, 0, 0], b"\x01" * 32))
    r = client.post(f"/elections/{EID_HEX}/ballots", json={"ballot": ballot})
    assert r.status_code == 200
    assert r.get_json()["sequenceNumber"] == 0
    assert fe.dl.count_ballots(fe.config.election_id) == 1


def test_gateway_rejects_outside_window(full_env):
    fe = full_env
    _ready(fe)
    fe.clock.set(500)  # before voting_start
    client = build_gateway_app(fe.dl, clock=fe.clock).test_client()
    ballot = codecs.enc_ballot(fe.voter_ballot([3, 0, 0], b"\x01" * 32))
    r = client.post(f"/elections/{EID_HEX}/ballots", json={"ballot": ballot})
    assert r.status_code == 400
    assert r.get_json()["error"] == "REJECTED"


def test_gateway_rejects_malformed(full_env):
    fe = full_env
    _ready(fe)
    fe.clock.set(1500)
    client = build_gateway_app(fe.dl, clock=fe.clock).test_client()
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
    on = build_gateway_app(fe.dl, clock=fe.clock, filter_on=True).test_client()
    assert on.post(f"/elections/{EID_HEX}/ballots", json={"ballot": codecs.enc_ballot(bad)}).status_code == 400
    # Filter off → accepted (injected); tally-time verification would exclude it.
    off = build_gateway_app(fe.dl, clock=fe.clock, filter_on=False).test_client()
    assert off.post(f"/elections/{EID_HEX}/ballots", json={"ballot": codecs.enc_ballot(bad)}).status_code == 200
