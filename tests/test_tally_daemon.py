"""Tally Aggregator watcher daemon: discover Tallying elections, aggregate,
trigger keypers over HTTP, finalize; Void past tally_deadline.

Full admin-plane pipeline end-to-end: auto-DKG finalizes the key, ballots go in
through the gateway, then the tally daemon drives aggregate → trigger → recover
against live keyper HTTP servers.
"""

from __future__ import annotations

import threading

import pytest
from werkzeug.serving import make_server

from geg.adapters.eligibility_stub import StubEligibilityService
from geg.adapters.memory import InMemoryDataLayer
from geg.core.authz import Signer
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.crypto import ballot as ballot_crypto, schnorr
from geg.crypto.points import g1_to_compressed, g2_from_compressed
from geg.envelopes.types import BallotEnvelope, Ciphertext
from geg.ports.eligibility import AttestationRequest
from geg.services import gateway
from geg.services.common.token_store import TokenStore
from geg.services.coordinator import AutoDKG
from geg.services.keyper import build_keyper_app
from geg.services.tally_aggregator import TallyAggregatorDaemon

from conftest import ManualClock

N, T = 3, 1


class World:
    def __init__(self, tmp_path):
        self.clock = ManualClock(0)
        self.dl = InMemoryDataLayer(clock=self.clock)
        self.coordinator = Signer.generate()
        self.admin = Signer.generate()
        self.aggregator = Signer.generate()
        self.gateway = Signer.generate()
        self.keyper_signers = [Signer.generate() for _ in range(N)]
        elig_sk, _ = schnorr.keygen()
        self.elig = StubEligibilityService(elig_sk)
        # Shared store: the coordinator writes keyper tokens, the aggregator reads them.
        self.token_store = TokenStore(tmp_path / "tokens")
        self._servers = []
        self.urls = {}
        for i in range(1, N + 1):
            # Keypers trust only the coordinator to bootstrap them (sole bootstrapper).
            app = build_keyper_app(self.keyper_signers[i - 1], self.dl,
                                   self.coordinator.identity,
                                   clock=self.clock, state_dir=tmp_path / f"k{i}")
            srv = make_server("127.0.0.1", 0, app, threaded=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self._servers.append(srv)
            self.urls[i] = f"http://127.0.0.1:{srv.server_port}"

    def shutdown(self):
        for s in self._servers:
            s.shutdown()

    def register(self, *, voting_start=1000, voting_end=2000, tally_deadline=3000) -> bytes:
        cfg = ElectionConfig(
            election_id=b"\x00" * 32, num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
            weighted=True, max_weight=10, duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=voting_start, voting_end=voting_end, tally_deadline=tally_deadline,
            threshold=Threshold(t=T, n=N),
            keypers=tuple(KeyperIdentity(signing_key=self.keyper_signers[i].identity, endpoint=self.urls[i + 1])
                          for i in range(N)),
            eligibility_key=self.elig.eligibility_key, aggregator_key=self.aggregator.identity,
            gateway_keys=(self.gateway.identity,), admin_key=self.admin.identity, protocol_version="v1",
        )
        return self.dl.register_election(cfg, self.admin.sign_register(cfg))

    def voter_ballot(self, eid, votes, pseudonym, weight):
        mpk = g2_from_compressed(self.dl.get_finalized_key(eid).pk_election)
        sk, vk = schnorr.keygen()
        vkb = g1_to_compressed(vk)
        built = ballot_crypto.build_ballot(mpk=mpk, election_id=eid, pseudonym=pseudonym, sk=sk, vk=vk,
                                           votes=votes, num_candidates=3, budget=3)
        att = self.elig.issue_attestation(AttestationRequest(eid, pseudonym, vkb, weight))
        return BallotEnvelope(election_id=eid, pseudonym=pseudonym, vk=vkb,
                              ciphertexts=tuple(Ciphertext(c1=a, c2=b) for (a, b) in built.ciphertexts),
                              zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att)


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    try:
        yield w
    finally:
        w.shutdown()


def test_tally_daemon_full_pipeline(world):
    w = world
    eid = w.register()
    AutoDKG(w.dl, w.coordinator, clock=w.clock, token_store=w.token_store).scan_once()  # finalize DKG + write tokens

    w.clock.set(1500)
    gateway.submit_ballot(w.dl, eid, w.voter_ballot(eid, [3, 0, 0], b"\x01" * 32, 2), clock=w.clock)
    gateway.submit_ballot(w.dl, eid, w.voter_ballot(eid, [0, 3, 0], b"\x02" * 32, 5), clock=w.clock)

    w.clock.set(2500)  # Tallying
    daemon = TallyAggregatorDaemon(w.dl, w.aggregator, clock=w.clock, hardened=True, token_store=w.token_store)
    outcomes = daemon.scan_once()

    assert outcomes[eid.hex()] == "tallied"
    result = w.dl.get_result(eid)
    assert result is not None and list(result.totals) == [6, 15, 0]


def test_tally_daemon_marks_void_past_deadline(world):
    w = world
    eid = w.register()
    AutoDKG(w.dl, w.coordinator, clock=w.clock).scan_once()
    # No ballots, no shares; jump past tally_deadline.
    w.clock.set(3500)
    daemon = TallyAggregatorDaemon(w.dl, w.aggregator, clock=w.clock)
    assert daemon.scan_once()[eid.hex()] == "void"
    assert w.dl.get_result(eid) is None
