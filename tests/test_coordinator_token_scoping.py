"""Per-keyper token scoping (Option D) — the coordinator→keyper channel credential.

A keyper's ``{api_token, peer_token}`` is a stable per-``(coordinator, keyper)``
credential: minted once, persisted by keyper URL, reused across every committee that
keyper joins, and never rotated by a new committee. Two guarantees are pinned here:

1. **No churn across overlapping concurrent committees.** Bootstrapping a second
   committee that shares members with the first must NOT rotate the shared keypers'
   tokens — otherwise the first election's coordinator→keyper calls start returning
   401 and it stalls. (Regression test for the confirmed concurrent-election bug.)
2. **401 safety net.** If a keyper doesn't hold the token the coordinator presents
   (state loss / never-installed credential), the trigger path re-installs that
   keyper's stable token and retries — so no coordinator→keyper call is left rejected.
"""

from __future__ import annotations

import threading

import pytest
import requests
from werkzeug.serving import make_server

from geg.adapters.memory import InMemoryDataLayer
from geg.core.authz import Signer
from geg.services.coordinator import dkg_coordinator as coord
from geg.services.common.token_store import TokenStore
from geg.services.keyper import build_keyper_app

from conftest import ManualClock

ANY_EID = (7).to_bytes(32, "big")


class Keypers:
    """A pool of live keyper HTTP servers sharing one coordinator + data layer."""

    def __init__(self, tmp_path, n):
        self.clock = ManualClock(0)
        self.dl = InMemoryDataLayer(clock=self.clock)
        self.coordinator = Signer.generate()
        self._servers = []
        self.urls = {}
        self.addr_by_url = {}
        for i in range(1, n + 1):
            signer = Signer.generate()
            app = build_keyper_app(signer, self.dl, self.coordinator.identity,
                                   clock=self.clock, state_dir=tmp_path / f"k{i}")
            srv = make_server("127.0.0.1", 0, app, threaded=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self._servers.append(srv)
            url = f"http://127.0.0.1:{srv.server_port}"
            self.urls[i] = url
            self.addr_by_url[url] = signer.identity

    def shutdown(self):
        for srv in self._servers:
            srv.shutdown()

    def member_addrs(self, committee):
        """Committee index → member address, for bootstrap_keypers' enc-pubkey verify."""
        return {ci: self.addr_by_url[url] for ci, url in committee.items()}

    def accepts(self, url, token):
        """True iff the keyper accepts this bearer (auth passes → not 401)."""
        r = requests.post(url.rstrip("/") + "/decrypt", json={"electionId": ANY_EID.hex()},
                          headers={"Authorization": f"Bearer {token}"})
        return r.status_code != 401


@pytest.fixture
def pool(tmp_path):
    p = Keypers(tmp_path, n=4)
    try:
        yield p
    finally:
        p.shutdown()


def test_overlapping_committee_does_not_churn_shared_keyper(pool, tmp_path):
    """committee1={k1,k2,k3}, then committee2={k2,k3,k4}: k2's token must survive."""
    store = TokenStore(tmp_path / "coord-state")

    c1 = {1: pool.urls[1], 2: pool.urls[2], 3: pool.urls[3]}
    api1, _ = coord.bootstrap_keypers(pool.coordinator, c1, member_addrs=pool.member_addrs(c1), token_store=store)
    k2_token = api1[2]
    assert pool.accepts(pool.urls[2], k2_token)  # k2 holds its committee1 token

    c2 = {1: pool.urls[2], 2: pool.urls[3], 3: pool.urls[4]}  # overlaps on k2, k3
    api2, _ = coord.bootstrap_keypers(pool.coordinator, c2, member_addrs=pool.member_addrs(c2), token_store=store)

    # k2's token is stable and still accepted — no churn.
    assert api2[1] == k2_token
    assert pool.accepts(pool.urls[2], k2_token)


def test_401_triggers_rebootstrap_and_retry(pool, tmp_path):
    """The coordinator presents a token the keyper doesn't hold (store divergence: the
    keyper holds token A, the coordinator re-minted B). The trigger path re-installs
    the coordinator's stable token and retries, so the call ends up accepted."""
    store = TokenStore(tmp_path / "coord-state")
    url = pool.urls[1]
    urls = {1: url}

    # Bootstrap normally: the keyper now holds token A (also in the store).
    api_a, _ = coord.bootstrap_keypers(pool.coordinator, urls, member_addrs=pool.member_addrs(urls), token_store=store)
    token_a = api_a[1]
    assert pool.accepts(url, token_a)

    # Diverge: the coordinator's store is re-minted to B, but the keyper still holds A.
    token_b = "re-minted-token-b"
    store.put(url, token_b, "re-minted-peer-b")
    api_tokens = {1: token_b}
    assert not pool.accepts(url, token_b)  # keyper holds A, not B → 401

    calls = {"n": 0}

    def rebootstrap(i):
        calls["n"] += 1
        toks, _ = coord.bootstrap_keypers(pool.coordinator, urls, member_addrs=pool.member_addrs(urls), token_store=store, install={i})
        return toks[i]

    coord.trigger_aggregate_http(ANY_EID, urls, api_tokens, rebootstrap=rebootstrap)

    assert calls["n"] == 1               # the 401 drove exactly one re-bootstrap
    assert api_tokens[1] == token_b      # the stable (store) token, re-installed on the keyper
    assert pool.accepts(url, token_b)    # keyper now accepts it → call recovered
