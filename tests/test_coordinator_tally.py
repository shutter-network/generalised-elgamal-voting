"""Coordinator as the single keyper-facing orchestrator: one ``AutoDKG`` drives an
election end to end — DKG, then (once Tallying) trigger keypers to aggregate → quorum
→ decrypt → recover + publish the result. The coordinator is also the result publisher
(``result_publisher_key == coordinator identity``).

Full admin-plane pipeline against live keyper HTTP servers.
"""

from __future__ import annotations

import threading

import pytest
from werkzeug.serving import make_server

from geg.adapters.eligibility_stub import StubEligibilityService
from geg.adapters.memory import InMemoryDataLayer
from geg.core.authz import Signer
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.crypto import ballot as ballot_crypto, binding, schnorr
from geg.crypto.points import g1_to_compressed, g2_from_compressed
from geg.envelopes.types import BallotEnvelope, Ciphertext
from geg.ports.eligibility import AttestationRequest
from geg.services import gateway
from geg.services.coordinator import AutoDKG
from geg.services.keyper import build_keyper_app

from conftest import ManualClock

N, T = 3, 2  # T is the quorum


class World:
    def __init__(self, tmp_path):
        self.clock = ManualClock(0)
        self.dl = InMemoryDataLayer(clock=self.clock)
        self.coordinator = Signer.generate()  # also the result publisher
        self.admin = Signer.generate()
        self.gateway = Signer.generate()
        self.keyper_signers = [Signer.generate() for _ in range(N)]
        elig_sk, _ = schnorr.keygen()
        self.elig = StubEligibilityService(elig_sk)
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

    def register(self, *, voting_start=1000, voting_end=2000) -> bytes:
        cfg = ElectionConfig(
            election_id=(1).to_bytes(32, "big"), num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
            weighted=True, duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=voting_start, voting_end=voting_end,
            threshold=Threshold(t=T, n=N),
            keypers=tuple(KeyperIdentity(signing_key=self.keyper_signers[i].identity, url=self.urls[i + 1])
                          for i in range(N)),
            eligibility_key=self.elig.eligibility_key, result_publisher_key=self.coordinator.identity,
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
                              zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att,
                              voter_attestation_signature=binding.sign_ballot_binding(
                                  voter_sk=sk, voter_vk=vk, election_id=eid, pseudonym=pseudonym,
                                  vk_bytes=vkb, ciphertexts=built.ciphertexts,
                                  zk_proof=built.zk_proof, attestation=att))


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    try:
        yield w
    finally:
        w.shutdown()


def test_coordinator_drives_dkg_then_tally(world):
    w = world
    eid = w.register()
    watcher = AutoDKG(w.dl, w.coordinator, clock=w.clock)
    watcher.scan_once()  # Registered → DKG finalizes (bootstraps + caches tokens)
    assert w.dl.get_finalized_key(eid) is not None

    w.clock.set(1500)  # voting open
    gateway.submit_ballot(w.dl, eid, w.voter_ballot(eid, [3, 0, 0], b"\x01" * 32, 2), clock=w.clock, gateway_signer=w.gateway)
    gateway.submit_ballot(w.dl, eid, w.voter_ballot(eid, [0, 3, 0], b"\x02" * 32, 5), clock=w.clock, gateway_signer=w.gateway)

    w.clock.set(2500)  # Tallying — same watcher now drives aggregate → decrypt → result
    # /aggregate is asynchronous: the first poll triggers it and gets 202 "started", so the
    # tally completes over several polls, exactly as the running coordinator does. A poll
    # that finds keypers still computing must NOT count as a failed attempt — that is what
    # used to stall healthy elections.
    import time as _t

    outcome = None
    for _ in range(300):
        outcome = watcher.scan_once()[eid.hex()]
        if outcome == "tallied":
            break
        assert outcome == "collecting_aggregate", outcome   # never abandoned while working
        _t.sleep(0.05)
    assert outcome == "tallied"
    result = w.dl.get_result(eid)
    assert result is not None and list(result.totals) == [6, 15, 0]
