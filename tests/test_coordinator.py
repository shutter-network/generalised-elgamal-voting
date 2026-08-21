"""Auto-DKG watcher: discovers elections needing a key via the data layer and
drives (and bootstraps) the keyper committee over HTTP.
"""

from __future__ import annotations

import threading

import pytest
from geg.core import authz
import requests
from werkzeug.serving import make_server

from geg.adapters.memory import InMemoryDataLayer
from geg.core.authz import Signer
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.services.coordinator import AutoDKG
from geg.services.keyper import build_keyper_app

from conftest import ManualClock

N, T = 3, 2  # T is the quorum


class KeyperWorld:
    def __init__(self, tmp_path):
        self.clock = ManualClock(0)
        self.dl = InMemoryDataLayer(clock=self.clock)
        self.coordinator = Signer.generate()
        self.admin = Signer.generate()
        self.keyper_signers = [Signer.generate() for _ in range(N)]

        self._servers = []
        self.urls = {}
        for i in range(1, N + 1):
            app = build_keyper_app(self.keyper_signers[i - 1], self.dl, self.coordinator.identity,
                                   clock=self.clock, state_dir=tmp_path / f"keyper{i}")
            srv = make_server("127.0.0.1", 0, app, threaded=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self._servers.append(srv)
            self.urls[i] = f"http://127.0.0.1:{srv.server_port}"

    def shutdown(self):
        for srv in self._servers:
            srv.shutdown()

    def register(self, *, voting_start=1000, voting_end=2000) -> bytes:
        config = ElectionConfig(
            # Assert the next id (the register replay guard); this env registers several.
            election_id=(len(self.dl.list_elections()) + 1).to_bytes(32, "big"),
            num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
            weighted=True, max_weight=10, duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=voting_start, voting_end=voting_end,
            threshold=Threshold(t=T, n=N),
            keypers=tuple(KeyperIdentity(signing_key=self.keyper_signers[i].identity, url=self.urls[i + 1])
                          for i in range(N)),
            eligibility_key=b"\xe1" * 48, result_publisher_key=self.coordinator.identity,  # coordinator = result publisher
            gateway_keys=(Signer.generate().identity,), admin_key=self.admin.identity, protocol_version="v1",
        )
        return self.dl.register_election(config, self.admin.sign_register(config))

    def watcher(self):
        return AutoDKG(self.dl, self.coordinator, clock=self.clock)


@pytest.fixture
def kw(tmp_path):
    w = KeyperWorld(tmp_path)
    try:
        yield w
    finally:
        w.shutdown()


def test_watcher_discovers_and_finalizes_dkg(kw):
    eid = kw.register()  # Registered (clock=0 < voting_start=1000)
    watcher = kw.watcher()

    outcomes = watcher.scan_once()
    assert outcomes[eid.hex()] == "finalized"
    assert kw.dl.get_finalized_key(eid) is not None


def test_watcher_bootstraps_the_keypers_itself(kw):
    eid = kw.register()
    # Before the watcher runs, no keyper is bootstrapped.
    assert requests.get(kw.urls[1] + "/status").json()["bootstrapped"] is False

    kw.watcher().scan_once()
    # The watcher (coordinator) installed the bearer tokens during the ceremony.
    assert requests.get(kw.urls[1] + "/status").json()["bootstrapped"] is True


def test_watcher_does_not_redrive_after_dkg(kw):
    eid = kw.register()
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    # Second pass: key finalized, election is KeyReady (pre-voting) → nothing to do
    # until it reaches Tallying. The DKG is not re-driven.
    assert watcher.scan_once()[eid.hex()] == "not_ready"


def test_watcher_marks_dkg_failed_past_voting_start(kw):
    eid = kw.register(voting_start=1000, voting_end=2000)
    kw.clock.set(1500)  # now > voting_start, still no key → terminally DKGFailed
    watcher = kw.watcher()

    assert watcher.scan_once()[eid.hex()] == "dkg_failed"
    assert kw.dl.get_finalized_key(eid) is None
    # Stays failed; not retried.
    assert watcher.scan_once()[eid.hex()] == "already_failed"


def test_watcher_drives_nearest_voting_start_first(kw, monkeypatch):
    from geg.services.coordinator import dkg_coordinator as coord

    # Registered out of order; expect drive order sorted by voting_start ascending.
    e_far = kw.register(voting_start=3000, voting_end=4000)
    e_near = kw.register(voting_start=1000, voting_end=2000)
    e_mid = kw.register(voting_start=2000, voting_end=3000)

    driven: list[bytes] = []
    real = coord.run_dkg_http
    monkeypatch.setattr(coord, "run_dkg_http",
                        lambda eid, *a, **k: (driven.append(eid), real(eid, *a, **k))[1])

    kw.watcher().scan_once()
    assert driven == [e_near, e_mid, e_far]
    assert all(kw.dl.get_finalized_key(e) is not None for e in (e_near, e_mid, e_far))


def test_watcher_ignores_elections_not_needing_dkg(kw):
    """A second election already past its window is handled without a crash;
    a fresh Registered one still gets finalized in the same pass."""
    done = kw.register()
    kw.watcher().scan_once()  # finalize it

    fresh = kw.register()
    outcomes = kw.watcher().scan_once()
    assert outcomes[done.hex()] == "not_ready"  # KeyReady: DKG done, not yet Tallying
    assert outcomes[fresh.hex()] == "finalized"


def test_watcher_halts_and_fails_on_dkg_complaint(kw, monkeypatch):
    """A Feldman-VSS complaint during round2 is terminal: the coordinator halts before
    publishing, marks the election failed, and does not retry it. (run_dkg_http raising
    DKGComplaint is covered in test_dkg_security; here we pin AutoDKG's reaction.)"""
    from geg.services.coordinator import dkg_coordinator as coord

    eid = kw.register()
    watcher = kw.watcher()

    def _complain(*_a, **_k):
        raise coord.DKGComplaint(
            "complaint against dealer(s) [2]",
            [{"electionId": eid.hex(), "accusedDealerIndex": 2, "recipientIndex": 1, "signature": "0xabcd"}])
    monkeypatch.setattr(coord, "run_dkg_http", _complain)  # real bootstrap, then a complaint

    assert watcher.scan_once()[eid.hex()] == "dkg_complaint"
    assert kw.dl.get_finalized_key(eid) is None            # halted before publish
    assert watcher.scan_once()[eid.hex()] == "already_failed"  # terminal, not retried


def test_watcher_abandons_tally_when_aggregate_never_reaches_quorum(kw, monkeypatch):
    """Tally has no natural deadline, so an under-quorum aggregate is bounded by
    max_tally_attempts polls, then abandoned (terminal + alert), not retriggered forever."""
    from geg.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"   # DKG done (clock=0)
    kw.clock.set(2500)                                     # → Tallying
    # Unreachable keypers: every trigger fails, which is what the attempt budget bounds.
    monkeypatch.setattr(coord, "trigger_aggregate_http", lambda *a, **k: {1: "failed", 2: "failed", 3: "failed"})

    outs = [watcher.scan_once()[eid.hex()] for _ in range(watcher.max_tally_attempts)]
    assert outs[:-1] == ["collecting_aggregate"] * (watcher.max_tally_attempts - 1)
    assert outs[-1] == "tally_abandoned"                   # 5th attempt → abandoned (flag set)
    assert kw.dl.get_election(eid).tally_stalled is True    # persisted for the dashboard
    assert watcher.scan_once()[eid.hex()] == "tally_stalled"  # now skipped (not re-driven)
    assert kw.dl.get_result(eid) is None


def test_stall_survives_restart_and_resumes_only_on_admin_clear(kw, monkeypatch):
    """The persisted flag is authoritative: a coordinator restart does NOT resurrect a
    stalled tally (it skips). Only the admin's clear (the retry) resumes it — with a fresh
    attempt budget."""
    from geg.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    w1 = kw.watcher()
    assert w1.scan_once()[eid.hex()] == "finalized"
    kw.clock.set(2500)
    monkeypatch.setattr(coord, "trigger_aggregate_http", lambda *a, **k: {1: "failed", 2: "failed", 3: "failed"})
    for _ in range(w1.max_tally_attempts):
        w1.scan_once()
    assert kw.dl.get_election(eid).tally_stalled is True

    # Restart: a fresh coordinator skips the stalled election (does NOT re-drive).
    w2 = kw.watcher()
    assert w2.scan_once()[eid.hex()] == "tally_stalled"
    assert kw.dl.get_election(eid).tally_stalled is True    # still stalled after restart

    # The admin clears it (the retry) → coordinator resumes with a fresh budget.
    kw.dl.set_tally_stalled(
        eid, False,
        kw.admin.sign("tally_resume", eid, authz.request_nonce_payload(int(kw.clock()))),
        int(kw.clock()))
    assert w2.scan_once()[eid.hex()] == "collecting_aggregate"  # resumed, retrying


def test_watcher_abandons_tally_when_decryption_never_finalizes(kw, monkeypatch):
    """A canonical aggregate forms but decryption shares never reach t+1 → the decrypt
    phase is also bounded by max_tally_attempts, then abandoned."""
    from geg.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    kw.clock.set(2500)
    monkeypatch.setattr(coord, "trigger_decrypt_http", lambda *a, **k: None)  # shares never land

    outs = [watcher.scan_once()[eid.hex()] for _ in range(watcher.max_tally_attempts)]
    assert outs[-1] == "tally_abandoned"                   # aggregate finalized, decrypt stalled → abandoned
    assert kw.dl.get_aggregate(eid) is not None            # the aggregate DID reach quorum
    assert kw.dl.get_result(eid) is None                   # but no result
    assert kw.dl.get_election(eid).tally_stalled is True   # persisted


def test_working_keypers_are_not_counted_as_failed_attempts(kw, monkeypatch):
    """A slow aggregate must not look like a stalled tally.

    Aggregation runs for minutes on a large election. Before /aggregate went async the
    coordinator timed out, read that as a failed attempt, and marked TallyStalled after
    five polls — on a committee that was working perfectly.
    """
    from geg.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    kw.clock.set(2500)
    monkeypatch.setattr(coord, "trigger_aggregate_http",
                        lambda *a, **k: {1: "in_progress", 2: "in_progress", 3: "started"})

    # Far more polls than max_tally_attempts: still waiting, never abandoned.
    for _ in range(watcher.max_tally_attempts * 3):
        assert watcher.scan_once()[eid.hex()] == "collecting_aggregate"
    assert kw.dl.get_election(eid).tally_stalled is False


def test_divergent_keypers_are_asked_to_re_derive_then_bounded(kw, monkeypatch):
    """All keypers submitted yet no t+1 quorum → they disagree.

    Divergence is often transient (one keyper read the ballot list a moment before
    another), and a keyper's aggregate stays overridable until the quorum freezes precisely
    so honest keypers can re-converge. So each attempt must actually ask them to re-derive
    — and the whole thing is still bounded, in case the divergence is permanent.
    """
    from geg.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    kw.clock.set(2500)

    recomputes = []

    def fake_trigger(*a, recompute=False, **k):
        recomputes.append(recompute)
        return {1: "submitted", 2: "submitted", 3: "submitted"}

    monkeypatch.setattr(coord, "trigger_aggregate_http", fake_trigger)

    outs = [watcher.scan_once()[eid.hex()] for _ in range(watcher.max_tally_attempts)]
    assert outs[:-1] == ["collecting_aggregate"] * (watcher.max_tally_attempts - 1)
    assert outs[-1] == "tally_abandoned"
    assert kw.dl.get_election(eid).tally_stalled is True
    # Every non-final poll asked the committee to re-derive — the convergence path.
    assert recomputes.count(True) == watcher.max_tally_attempts - 1


def test_tally_phase_deadline_is_the_backstop(kw, monkeypatch):
    """Keypers claim to be working forever → the wall-clock budget ends it. Measured from
    voting_end, so it is derived and survives a coordinator restart."""
    from geg.services.coordinator import dkg_coordinator as coord

    eid = kw.register(voting_start=1000, voting_end=2000)
    watcher = kw.watcher()
    assert watcher.scan_once()[eid.hex()] == "finalized"
    monkeypatch.setattr(coord, "trigger_aggregate_http", lambda *a, **k: {1: "in_progress"})

    kw.clock.set(2500)                                    # just past voting_end
    assert watcher.scan_once()[eid.hex()] == "collecting_aggregate"
    kw.clock.set(2000 + int(watcher.max_tally_phase_s) + 1)   # past the deadline
    assert watcher.scan_once()[eid.hex()] == "tally_abandoned"
    assert kw.dl.get_election(eid).tally_stalled is True
