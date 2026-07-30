"""Auto-DKG watcher: discovers elections needing a key via the data layer and
drives (and bootstraps) the keyper committee over HTTP.
"""

from __future__ import annotations

import threading

import pytest
import requests
from werkzeug.serving import make_server

from geg.adapters.memory import InMemoryDataLayer
from geg.core.authz import Signer
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.services.coordinator import AutoDKG
from geg.services.keyper import build_keyper_app

from conftest import ManualClock

N, T = 3, 1


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

    def register(self, *, voting_start=1000, voting_end=2000, tally_deadline=3000) -> bytes:
        config = ElectionConfig(
            election_id=b"\x00" * 32, num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
            weighted=True, max_weight=10, duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=voting_start, voting_end=voting_end, tally_deadline=tally_deadline,
            threshold=Threshold(t=T, n=N),
            keypers=tuple(KeyperIdentity(signing_key=self.keyper_signers[i].identity, url=self.urls[i + 1])
                          for i in range(N)),
            eligibility_key=b"\xe1" * 48, result_publisher_key=Signer.generate().identity,
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
    eid = kw.register(voting_start=1000, voting_end=2000, tally_deadline=3000)
    kw.clock.set(1500)  # now > voting_start, still no key → terminally DKGFailed
    watcher = kw.watcher()

    assert watcher.scan_once()[eid.hex()] == "dkg_failed"
    assert kw.dl.get_finalized_key(eid) is None
    # Stays failed; not retried.
    assert watcher.scan_once()[eid.hex()] == "already_failed"


def test_watcher_drives_nearest_voting_start_first(kw, monkeypatch):
    from geg.services.coordinator import dkg_coordinator as coord

    # Registered out of order; expect drive order sorted by voting_start ascending.
    e_far = kw.register(voting_start=3000, voting_end=4000, tally_deadline=5000)
    e_near = kw.register(voting_start=1000, voting_end=2000, tally_deadline=3000)
    e_mid = kw.register(voting_start=2000, voting_end=3000, tally_deadline=4000)

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
