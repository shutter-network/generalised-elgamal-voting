"""Multi-operator keyper backend: DKG over HTTP → decrypt → tally (sx-monorepo model).

Spins up n keyper HTTP servers (each with its own identity + private encrypted
state dir), bootstraps bearer tokens, drives a real distributed DKG over the wire
(confidential round-2 shares travel keyper→keyper), then runs a full weighted
election to a correct tally — with keypers triggered over HTTP and self-guarding
via the §8.2 preconditions. Also checks auth fail-closed and persisted-secret
restart.
"""

from __future__ import annotations

import threading

import pytest
import requests
from werkzeug.serving import make_server

from geg.adapters.eligibility_stub import StubEligibilityService
from geg.adapters.memory import InMemoryDataLayer
from geg.core.authz import Signer
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.crypto import ballot as ballot_crypto
from geg.crypto import schnorr
from geg.crypto.points import g1_to_compressed, g2_from_compressed
from geg.envelopes.types import BallotEnvelope, Ciphertext
from geg.ports.eligibility import AttestationRequest
from geg.services.coordinator import dkg_coordinator as coord
from geg.services import tally_aggregator as agg
from geg.services.gateway import submit_ballot
from geg.services.keyper import build_keyper_app

from conftest import ManualClock

ELECTION_ID = (1).to_bytes(32, "big")
N, T = 3, 1


class World:
    def __init__(self, tmp_path):
        self.clock = ManualClock(0)
        self.dl = InMemoryDataLayer(clock=self.clock)
        self.coordinator = Signer.generate()
        self.admin = Signer.generate()
        self.result_publisher = Signer.generate()
        self.gateway = Signer.generate()
        self.keyper_signers = [Signer.generate() for _ in range(N)]
        elig_sk, _ = schnorr.keygen()
        self.elig = StubEligibilityService(elig_sk)

        self.config = ElectionConfig(
            election_id=ELECTION_ID, num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
            weighted=True, max_weight=10, duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=1000, voting_end=2000, tally_deadline=3000, threshold=Threshold(t=T, n=N),
            keypers=tuple(KeyperIdentity(signing_key=self.keyper_signers[i].identity, endpoint="") for i in range(N)),
            eligibility_key=self.elig.eligibility_key, result_publisher_key=self.result_publisher.identity,
            gateway_keys=(self.gateway.identity,), admin_key=self.admin.identity, protocol_version="v1",
        )
        self.dl.register_election(self.config, self.admin.sign_register(self.config))

        self._servers = []
        self.keyper_urls = {}
        self.state_dirs = {}
        for i in range(1, N + 1):
            sd = tmp_path / f"keyper{i}"
            self.state_dirs[i] = sd
            app = build_keyper_app(self.keyper_signers[i - 1], self.dl, self.coordinator.identity,
                                   clock=self.clock, state_dir=sd)
            srv = make_server("127.0.0.1", 0, app, threaded=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self._servers.append(srv)
            self.keyper_urls[i] = f"http://127.0.0.1:{srv.server_port}"

    def shutdown(self):
        for srv in self._servers:
            srv.shutdown()

    def voter_ballot(self, votes, pseudonym, weight=1):
        mpk = g2_from_compressed(self.dl.get_finalized_key(ELECTION_ID).pk_election)
        sk, vk = schnorr.keygen()
        vkb = g1_to_compressed(vk)
        built = ballot_crypto.build_ballot(mpk=mpk, election_id=ELECTION_ID, pseudonym=pseudonym,
                                           sk=sk, vk=vk, votes=votes, num_candidates=3, budget=3)
        att = self.elig.issue_attestation(AttestationRequest(ELECTION_ID, pseudonym, vkb, weight))
        return BallotEnvelope(election_id=ELECTION_ID, pseudonym=pseudonym, vk=vkb,
                              ciphertexts=tuple(Ciphertext(c1=a, c2=b) for (a, b) in built.ciphertexts),
                              zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att)


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    try:
        yield w
    finally:
        w.shutdown()


def _bootstrap_and_dkg(w):
    api_tokens, _peer = coord.bootstrap_keypers(w.coordinator, w.keyper_urls)
    assert coord.run_dkg_http(ELECTION_ID, w.keyper_urls, api_tokens, w.dl)
    return api_tokens


# --------------------------------------------------------------------------- #
#  Full multi-operator flow
# --------------------------------------------------------------------------- #

def test_distributed_dkg_then_decrypt_then_tally(world):
    w = world
    api_tokens = _bootstrap_and_dkg(w)
    assert w.dl.get_finalized_key(ELECTION_ID) is not None

    # Vote (weighted) through the gateway during the voting window.
    w.clock.set(1500)
    submit_ballot(w.dl, ELECTION_ID, w.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2), clock=w.clock)
    submit_ballot(w.dl, ELECTION_ID, w.voter_ballot([0, 3, 0], b"\x02" * 32, weight=5), clock=w.clock)

    # Tally: keypers aggregate over HTTP (quorum → canonical), trigger decrypt, finalize.
    w.clock.set(2500)
    coord.trigger_aggregate_http(ELECTION_ID, w.keyper_urls, api_tokens)
    assert w.dl.get_aggregate(ELECTION_ID) is not None  # t+1 keypers agreed → canonical
    coord.trigger_decrypt_http(ELECTION_ID, w.keyper_urls, api_tokens)
    result = agg.finalize(w.dl, ELECTION_ID, w.result_publisher, clock=w.clock)

    assert result is not None
    assert list(result.totals) == [6, 15, 0]  # [2*3, 5*3, 0]


def test_aggregate_after_quorum_is_benign_not_500(world):
    """A keyper whose (byte-identical) aggregate lands *after* the t+1 quorum froze the
    canonical aggregate must get a clean 200, not a 500. With n>t+1 this is normal: the
    last keyper's submission is simply not needed."""
    w = world
    api_tokens = _bootstrap_and_dkg(w)
    w.clock.set(1500)
    submit_ballot(w.dl, ELECTION_ID, w.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2), clock=w.clock)
    w.clock.set(2500)

    def post_aggregate(i):
        return requests.post(w.keyper_urls[i] + "/aggregate", json={"electionId": ELECTION_ID.hex()},
                             headers={"Authorization": f"Bearer {api_tokens[i]}"})

    # First two keypers reach the t+1 (=2) quorum → aggregate canonical and frozen.
    assert post_aggregate(1).status_code == 200
    assert post_aggregate(2).status_code == 200
    assert w.dl.get_aggregate(ELECTION_ID) is not None

    # The third keyper's tardy, byte-identical submission is now a benign no-op.
    r = post_aggregate(3)
    assert r.status_code == 200, r.text
    assert "already finalized" in r.json().get("note", "")


# --------------------------------------------------------------------------- #
#  Auth (fail-closed) + P2P confidentiality routing
# --------------------------------------------------------------------------- #

def test_endpoints_reject_without_token(world):
    w = world
    url = w.keyper_urls[1]
    # Before bootstrap → fail-closed (503).
    r = requests.post(url + "/dkg/round1", json={"electionId": ELECTION_ID.hex()})
    assert r.status_code == 503

    api_tokens = _bootstrap_and_dkg(w)
    # Wrong token → 401.
    r = requests.post(url + "/dkg/round1", json={"electionId": ELECTION_ID.hex()},
                      headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
    # Coordinator (api) token on a peer-only endpoint → 401.
    r = requests.post(url + "/dkg/receive_share",
                      json={"electionId": ELECTION_ID.hex(), "dealerIndex": 2, "recipientIndex": 1, "share": "0x1"},
                      headers={"Authorization": f"Bearer {api_tokens[1]}"})
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
#  Persisted secrets survive a restart
# --------------------------------------------------------------------------- #

def test_restart_reloads_persisted_secret_and_tokens(world, tmp_path):
    w = world
    _bootstrap_and_dkg(w)

    # A "restarted" keyper 1: same signing key + same state dir, fresh app instance.
    app2 = build_keyper_app(w.keyper_signers[0], w.dl, w.coordinator.identity,
                            clock=w.clock, state_dir=w.state_dirs[1])
    client = app2.test_client()
    status = client.get("/status").get_json()
    assert status["bootstrapped"] is True  # tokens loaded from disk
    assert ELECTION_ID.hex() in status["elections"]  # DKG secret loaded from disk
