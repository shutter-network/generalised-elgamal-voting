"""Multi-operator keyper backend: DKG over HTTP → decrypt → tally.

Spins up n keyper HTTP servers (each with its own identity + private encrypted
state dir), bootstraps bearer tokens, drives a real distributed DKG over the wire
(confidential round-2 shares travel keyper→keyper), then runs a full weighted
election to a correct tally — with keypers triggered over HTTP and self-guarding
via their preconditions. Also checks auth fail-closed and persisted-secret
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
from geg.crypto import ballot as ballot_crypto, binding
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
N, T = 3, 2  # T is the quorum


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
            weighted=True, duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=1000, voting_end=2000, threshold=Threshold(t=T, n=N),
            keypers=tuple(KeyperIdentity(signing_key=self.keyper_signers[i].identity, url="") for i in range(N)),
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
                              zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att,
                              voter_attestation_signature=binding.sign_ballot_binding(
                                  voter_sk=sk, voter_vk=vk, election_id=ELECTION_ID, pseudonym=pseudonym,
                                  vk_bytes=vkb, ciphertexts=built.ciphertexts,
                                  zk_proof=built.zk_proof, attestation=att))


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    try:
        yield w
    finally:
        w.shutdown()


def _wait_for_aggregate(w, timeout=30.0):
    """Block until a quorum of keypers makes an aggregate canonical.

    `/aggregate` is asynchronous — it returns 202 and computes on a worker thread, because
    verifying every ballot inline blocked the coordinator's trigger and made a healthy but
    slow keyper look like a stalled tally. So callers poll for the result.
    """
    import time as _t

    deadline = _t.time() + timeout
    while _t.time() < deadline:
        agg = w.dl.get_aggregate(ELECTION_ID)
        if agg is not None:
            return agg
        _t.sleep(0.05)
    raise AssertionError(f"no canonical aggregate within {timeout}s")


def _bootstrap_and_dkg(w):
    api_tokens, _peer = coord.bootstrap_keypers(
        w.coordinator, w.keyper_urls,
        member_addrs={i: w.keyper_signers[i - 1].identity for i in w.keyper_urls})
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
    submit_ballot(w.dl, ELECTION_ID, w.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2), clock=w.clock, gateway_signer=w.gateway)
    submit_ballot(w.dl, ELECTION_ID, w.voter_ballot([0, 3, 0], b"\x02" * 32, weight=5), clock=w.clock, gateway_signer=w.gateway)

    # Tally: keypers aggregate over HTTP (quorum → canonical), trigger decrypt, finalize.
    w.clock.set(2500)
    coord.trigger_aggregate_http(ELECTION_ID, w.keyper_urls, api_tokens)
    assert _wait_for_aggregate(w) is not None  # a quorum of keypers agreed → canonical
    coord.trigger_decrypt_http(ELECTION_ID, w.keyper_urls, api_tokens)
    result = agg.finalize(w.dl, ELECTION_ID, w.result_publisher, clock=w.clock)

    assert result is not None
    assert list(result.totals) == [6, 15, 0]  # [2*3, 5*3, 0]


def test_aggregate_after_quorum_is_benign_not_500(world):
    """A keyper whose (byte-identical) aggregate lands *after* the quorum froze the
    canonical aggregate must get a clean 200, not a 500. With n > quorum this is normal:
    the last keyper's submission is simply not needed."""
    w = world
    api_tokens = _bootstrap_and_dkg(w)
    w.clock.set(1500)
    submit_ballot(w.dl, ELECTION_ID, w.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2), clock=w.clock, gateway_signer=w.gateway)
    w.clock.set(2500)

    def post_aggregate(i):
        return requests.post(w.keyper_urls[i] + "/aggregate", json={"electionId": ELECTION_ID.hex()},
                             headers={"Authorization": f"Bearer {api_tokens[i]}"})

    # First two keypers reach the quorum (T=2) → aggregate canonical and frozen.
    assert post_aggregate(1).status_code == 202          # accepted, computing
    assert post_aggregate(2).status_code == 202
    assert _wait_for_aggregate(w) is not None

    # The third keyper's tardy, byte-identical submission is a benign no-op: it is accepted,
    # runs, discovers the quorum froze the identical artifact first, and finishes cleanly
    # rather than erroring.
    assert post_aggregate(3).status_code == 202
    import time as _t
    for _ in range(200):
        r = post_aggregate(3)
        if r.json().get("status") == "submitted":
            break
        _t.sleep(0.05)
    assert r.status_code == 200 and r.json()["status"] == "submitted", r.text


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

    # A hostile bearer must still be a clean 401 — never a 500. The compare is
    # constant-time now, and `hmac.compare_digest` raises TypeError on a non-ASCII *str*,
    # so comparing the header string directly would hand any client a 500 for one byte.
    # The reachable inputs are latin-1: HTTP headers are latin-1 on the wire and werkzeug
    # decodes them as latin-1, so "tök" is sendable and arrives as a non-ASCII str, while
    # something like "Ω" cannot be put in a header at all. Prefix/extension cases included
    # because those are exactly what a timing oracle would be walked through.
    real = api_tokens[1]
    for hostile in ["tök", "\xff\xfe", "tok\xe9", real[:-1], real + "x", "", "   "]:
        r = requests.post(url + "/dkg/round1", json={"electionId": ELECTION_ID.hex()},
                          headers={"Authorization": f"Bearer {hostile}"})
        assert r.status_code == 401, f"{hostile!r} gave {r.status_code}, expected 401"

    # ...and the genuine token still authenticates (guards against over-strict rejection).
    r = requests.post(url + "/dkg/round1", json={"electionId": ELECTION_ID.hex()},
                      headers={"Authorization": f"Bearer {real}"})
    assert r.status_code != 401


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


def test_coordinator_driven_dkg_never_publishes_a_key_for_a_rogue_dealer(world, monkeypatch, caplog):
    """The commitment-count guard through the REAL coordinator: `run_dkg_http` driving live keyper servers with a
    dealer that publishes t+2 commitments must never finalize a key.

    Models the attack at its source — the rogue keyper's own `round1` deals a degree-(t+1)
    polynomial, so every share it hands out still satisfies Feldman verification. Before the
    fix this ceremony finalized cleanly and the election became untalliable at tally time.

    This covers the **naive** rogue, which propagates its peers' rejections: honest keypers
    refuse the vector at ingest (400), so the rogue's own `distribute_commitments` fails and
    the coordinator aborts the phase with an error naming keyper 2. `_drive_dkg` then backs
    off and retries until `voting_start`, where the election derives to `DKGFailed`.

    The **malicious** rogue — one running patched code that swallows those rejections and
    reports success — is covered by
    `test_dkg_security.py::test_over_long_commitments_halt_the_ceremony_with_the_dealer_named`,
    where the ceremony reaches round 2 and honest keypers emit signed accusations naming the
    dealer. Both adversaries end with no finalized key; they differ only in which guard
    fires first and how the fault is reported.
    """
    import logging

    from geg.crypto.dkg import KeyperDKGState

    orig = KeyperDKGState.round1
    rogue_id = 2

    def rogue_round1(self, keyper_id, n, quorum):
        # One degree too many, but only for the rogue: honest dealers are untouched.
        # round1 emits `quorum` commitments, so quorum+1 is exactly one over.
        return orig(self, keyper_id, n, quorum + 1 if keyper_id == rogue_id else quorum)

    monkeypatch.setattr(KeyperDKGState, "round1", rogue_round1)

    w = world
    api_tokens, _peer = coord.bootstrap_keypers(
        w.coordinator, w.keyper_urls,
        member_addrs={i: w.keyper_signers[i - 1].identity for i in w.keyper_urls})

    caplog.set_level(logging.WARNING)
    with pytest.raises(Exception):
        coord.run_dkg_http(ELECTION_ID, w.keyper_urls, api_tokens, w.dl)

    # The property that matters: no key was finalized, so the election can never reach a
    # state where ballots are cast against a key whose tally cannot be recovered.
    assert w.dl.get_finalized_key(ELECTION_ID) is None
    # And the rogue is identified in the record, not merely "something went wrong".
    assert any("bad_commitment_count" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- #
#  Asynchronous /aggregate (slow tally != stalled tally)
# --------------------------------------------------------------------------- #

def test_aggregate_returns_immediately_and_never_starts_a_second_worker(world, monkeypatch):
    """The guard the whole design rests on.

    The coordinator re-triggers /aggregate every poll. If each trigger spawned another
    worker, a long aggregation would accumulate one full ballot re-verification per poll
    and the keyper would collapse under its own retries before finishing a single pass.
    So a re-trigger while work is in flight must report in_progress and start nothing.
    """
    import time as _t

    from geg.services.keyper.keyper import KeyperService

    w = world
    api_tokens = _bootstrap_and_dkg(w)
    w.clock.set(1500)
    submit_ballot(w.dl, ELECTION_ID, w.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2),
                  clock=w.clock, gateway_signer=w.gateway)
    w.clock.set(2500)

    # Make aggregation slow enough to observe, and count how many times it actually runs.
    runs = []
    real = KeyperService.produce_aggregate

    def slow(self, election_id):
        runs.append(1)
        _t.sleep(1.0)
        return real(self, election_id)

    monkeypatch.setattr(KeyperService, "produce_aggregate", slow)

    def post(i):
        return requests.post(w.keyper_urls[i] + "/aggregate", json={"electionId": ELECTION_ID.hex()},
                             headers={"Authorization": f"Bearer {api_tokens[i]}"})

    t0 = _t.time()
    first = post(1)
    elapsed = _t.time() - t0
    assert first.status_code == 202 and first.json()["status"] == "started"
    assert elapsed < 0.5, f"trigger blocked for {elapsed:.2f}s — it must not wait for the work"

    # Hammer it the way the coordinator would while the worker is busy.
    for _ in range(5):
        r = post(1)
        assert r.status_code == 202 and r.json()["status"] == "in_progress"

    for _ in range(100):                      # let the single worker finish
        if post(1).json().get("status") == "submitted":
            break
        _t.sleep(0.05)
    assert post(1).json()["status"] == "submitted"
    assert len(runs) == 1, f"expected exactly one aggregation, got {len(runs)}"


def test_recompute_forces_a_fresh_derivation_after_submitting(world, monkeypatch):
    """The committee's convergence path.

    A keyper's aggregate is overridable until the quorum freezes, so honest keypers can
    re-converge after a transient divergence. That only works if a re-trigger actually
    re-derives — a plain trigger must NOT (it would burn minutes of CPU on every poll
    while merely waiting for slower peers), but `recompute` must.
    """
    import time as _t

    from geg.services.keyper.keyper import KeyperService

    w = world
    api_tokens = _bootstrap_and_dkg(w)
    w.clock.set(1500)
    submit_ballot(w.dl, ELECTION_ID, w.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2),
                  clock=w.clock, gateway_signer=w.gateway)
    w.clock.set(2500)

    runs = []
    real = KeyperService.produce_aggregate
    monkeypatch.setattr(KeyperService, "produce_aggregate",
                        lambda self, eid: (runs.append(1), real(self, eid))[1])

    def post(**body):
        return requests.post(w.keyper_urls[1] + "/aggregate",
                             json={"electionId": ELECTION_ID.hex(), **body},
                             headers={"Authorization": f"Bearer {api_tokens[1]}"})

    assert post().status_code == 202
    for _ in range(100):
        if post().json().get("status") == "submitted":
            break
        _t.sleep(0.05)
    assert post().json()["status"] == "submitted"
    assert len(runs) == 1

    # A plain re-trigger changes nothing ...
    assert post().json()["status"] == "submitted"
    assert len(runs) == 1, "a plain trigger must not recompute"

    # ... but an explicit recompute re-derives once more.
    r = post(recompute=True)
    assert r.status_code == 202 and r.json()["status"] == "started"
    for _ in range(100):
        if post().json().get("status") == "submitted":
            break
        _t.sleep(0.05)
    assert len(runs) == 2, f"recompute must re-derive exactly once more, got {len(runs)}"
