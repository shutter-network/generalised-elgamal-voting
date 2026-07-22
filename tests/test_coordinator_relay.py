"""Coordinator write-relay endpoints: keypers submit signed artifacts, the
coordinator relays them to the data layer (bearer-gated, fail-closed).

Mirrors the data layer's dkg/share writes but exercised through the coordinator's
``/dkg-result`` and ``/decryption-share`` endpoints over the in-memory backend.
"""

from __future__ import annotations

import threading

from werkzeug.serving import make_server

from geg.core import write_auth
from geg.adapters.memory import InMemoryDataLayer
from geg.core.authz import Signer
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.envelopes import codecs
from geg.envelopes.types import DecryptionShareEntry, DecryptionShareEnvelope
from geg.services.coordinator import dkg_coordinator as coord
from geg.services.coordinator import CoordinatorClient, build_coordinator_app
from geg.services.keyper import build_keyper_app

from conftest import ManualClock

TOKEN = "coord-token"
N, T, NC = 3, 1, 3


def _world():
    dl = InMemoryDataLayer(clock=ManualClock(0))
    admin = Signer.generate()
    keypers = [Signer.generate() for _ in range(N)]
    cfg = ElectionConfig(
        election_id=b"\x00" * 32, num_candidates=NC, budget=3, mode=Mode.EXACT, variant=Variant.A,
        weighted=True, max_weight=10, duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=1_000, voting_end=2_000, tally_deadline=3_000, threshold=Threshold(t=T, n=N),
        keypers=tuple(KeyperIdentity(signing_key=keypers[i].identity, endpoint="") for i in range(N)),
        eligibility_key=b"\xe1" * 48, aggregator_key=Signer.generate().identity,
        gateway_keys=(Signer.generate().identity,), admin_key=admin.identity, protocol_version="v1",
    )
    eid = dl.register_election(cfg, admin.sign_register(cfg))
    return dl, eid, keypers


def _dkg_body(eid, keyper, pk, committee):
    sig = write_auth.sign_dkg_result(keyper.private_key, eid, pk, committee)
    return {
        "electionId": codecs.enc_bytes(eid), "pkElection": codecs.enc_bytes(pk),
        "committeePKs": [codecs.enc_bytes(c) for c in committee], "keyperSig": codecs.enc_bytes(sig),
    }


def _share(eid, index):
    return DecryptionShareEnvelope(
        election_id=eid, keyper_index=index,
        entries=tuple(DecryptionShareEntry(sigma=bytes([9]) * 96, proof=bytes([0x0A]) * 64) for _ in range(NC)),
    )


def _share_body(eid, keyper, share):
    sigmas = [e.sigma for e in share.entries]
    proofs = [(int.from_bytes(e.proof[:32], "big"), int.from_bytes(e.proof[32:], "big")) for e in share.entries]
    sig = write_auth.sign_decryption_share(keyper.private_key, eid, sigmas, proofs)
    return {"electionId": codecs.enc_bytes(eid), "share": codecs.enc_decryption_share(share),
            "keyperSig": codecs.enc_bytes(sig)}


def _client(dl, token=TOKEN):
    return build_coordinator_app(dl, api_token=token).test_client()


def test_relay_dkg_result_reaches_quorum():
    dl, eid, keypers = _world()
    c = _client(dl)
    hdr = {"Authorization": f"Bearer {TOKEN}"}
    pk = bytes([0xA0]) * 96
    committee = [bytes([0xA1 + i]) * 96 for i in range(N)]
    assert c.post("/dkg-result", json=_dkg_body(eid, keypers[0], pk, committee), headers=hdr).status_code == 204
    assert dl.get_finalized_key(eid) is None                                    # 1 < t+1
    assert c.post("/dkg-result", json=_dkg_body(eid, keypers[1], pk, committee), headers=hdr).status_code == 204
    fk = dl.get_finalized_key(eid)
    assert fk is not None and fk.pk_election == pk                              # quorum → canonical


def test_relay_decryption_share():
    dl, eid, keypers = _world()
    c = _client(dl)
    hdr = {"Authorization": f"Bearer {TOKEN}"}
    assert c.post("/decryption-share", json=_share_body(eid, keypers[0], _share(eid, 1)), headers=hdr).status_code == 204
    assert len(dl.list_decryption_shares(eid)) == 1


def test_relay_requires_token():
    dl, eid, keypers = _world()
    c = _client(dl)
    pk = bytes([0xA0]) * 96
    committee = [bytes([0xA1 + i]) * 96 for i in range(N)]
    body = _dkg_body(eid, keypers[0], pk, committee)
    assert c.post("/dkg-result", json=body).status_code == 401                                   # missing
    assert c.post("/dkg-result", json=body, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_relay_failclosed_without_configured_token():
    dl, eid, keypers = _world()
    c = _client(dl, token=None)
    pk = bytes([0xA0]) * 96
    committee = [bytes([0xA1 + i]) * 96 for i in range(N)]
    r = c.post("/dkg-result", json=_dkg_body(eid, keypers[0], pk, committee),
               headers={"Authorization": "Bearer anything"})
    assert r.status_code == 503


def test_relay_non_keyper_rejected():
    dl, eid, _keypers = _world()
    c = _client(dl)
    stranger = Signer.generate()  # not a committee member
    pk = bytes([0xA0]) * 96
    committee = [bytes([0xA1 + i]) * 96 for i in range(N)]
    r = c.post("/dkg-result", json=_dkg_body(eid, stranger, pk, committee),
               headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 403  # data layer recovers a non-member → WriteAuthorizationError


def test_health_open():
    dl, _eid, _keypers = _world()
    assert _client(dl).get("/health").status_code == 200


def test_keypers_write_dkg_through_coordinator_relay(tmp_path):
    """End-to-end redirect: keyper servers POST their signed DKG result to the
    coordinator relay (submitter=CoordinatorClient), which writes it to the data
    layer — the keyper never writes to the data layer itself."""
    dl = InMemoryDataLayer(clock=ManualClock(0))
    admin = Signer.generate()
    coordinator = Signer.generate()
    keypers = [Signer.generate() for _ in range(N)]
    cfg = ElectionConfig(
        election_id=b"\x00" * 32, num_candidates=NC, budget=3, mode=Mode.EXACT, variant=Variant.A,
        weighted=True, max_weight=10, duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=1_000, voting_end=2_000, tally_deadline=3_000, threshold=Threshold(t=T, n=N),
        keypers=tuple(KeyperIdentity(signing_key=keypers[i].identity, endpoint="") for i in range(N)),
        eligibility_key=b"\xe1" * 48, aggregator_key=Signer.generate().identity,
        gateway_keys=(Signer.generate().identity,), admin_key=admin.identity, protocol_version="v1",
    )
    eid = dl.register_election(cfg, admin.sign_register(cfg))

    servers = []

    def serve(app):
        srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_port}"

    try:
        relay_url = serve(build_coordinator_app(dl, api_token=TOKEN))
        submitter = CoordinatorClient(relay_url, TOKEN)
        keyper_urls = {}
        for i in range(1, N + 1):
            app = build_keyper_app(keypers[i - 1], dl, coordinator.identity,
                                   clock=lambda: 0, state_dir=tmp_path / f"k{i}", submitter=submitter)
            keyper_urls[i] = serve(app)

        api_tokens, _peer = coord.bootstrap_keypers(coordinator, keyper_urls)
        assert coord.run_dkg_http(eid, keyper_urls, api_tokens, dl)   # writes flow keyper→relay→dl
        assert dl.get_finalized_key(eid) is not None
    finally:
        for srv in servers:
            srv.shutdown()
