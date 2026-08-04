"""Admin HTTP service: register/cancel over HTTP, authorized by a relayed admin
**signature** (auth model B — no bearer token).

The admin EOA signs the request (here we sign locally, standing in for the frontend
wallet); the service verifies the signature recovers to the admin identity and relays it.
Driven over the in-memory data layer via the Flask test client.
"""

from __future__ import annotations

from geg.adapters.memory import InMemoryDataLayer
from geg.core.authz import Signer
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.envelopes import codecs
from geg.services.admin import build_admin_app

from conftest import ManualClock


def _config(admin: Signer) -> ElectionConfig:
    keypers = [Signer.generate() for _ in range(3)]
    return ElectionConfig(
        election_id=b"\x00" * 32, num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
        weighted=True, max_weight=10, duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=1_000, voting_end=2_000, threshold=Threshold(t=1, n=3),
        keypers=tuple(KeyperIdentity(signing_key=keypers[i].identity, url=f"http://keyper{i+1}:8100")
                      for i in range(3)),
        eligibility_key=b"\xe1" * 48, result_publisher_key=Signer.generate().identity,
        gateway_keys=(Signer.generate().identity,), admin_key=admin.identity, protocol_version="v1",
    )


def _app():
    admin = Signer.generate()
    dl = InMemoryDataLayer(clock=ManualClock(0))
    app = build_admin_app(dl, admin.identity, clock=lambda: 0)
    return app, admin, dl


def _register_body(cfg, signer: Signer, dkg_lead_time: int = 0):
    return {"config": codecs.enc_config(cfg), "signature": codecs.enc_bytes(signer.sign_register(cfg)),
            "dkgLeadTime": dkg_lead_time}


def test_health_is_open():
    app, _admin, _dl = _app()
    assert app.test_client().get("/health").status_code == 200


def test_register_requires_valid_admin_signature():
    app, admin, _dl = _app()
    c = app.test_client()
    cfg = _config(admin)
    # a signature from the wrong key (not config.admin_key) → 401
    bad = c.post("/elections", json=_register_body(cfg, Signer.generate()))
    assert bad.status_code == 401
    # the admin EOA's signature → 200, registry-assigned id 1
    r = c.post("/elections", json=_register_body(cfg, admin))
    assert r.status_code == 200
    assert r.get_json()["electionId"] == "0x" + (1).to_bytes(32, "big").hex()


def test_register_rejects_admin_key_mismatch():
    # config.admin_key is a different EOA than the service's admin identity → 400,
    # even though the signature over the config is itself valid.
    app, _admin, _dl = _app()
    other = Signer.generate()
    r = app.test_client().post("/elections", json=_register_body(_config(other), other))
    assert r.status_code == 400  # RegistrationError (admin identity mismatch)


def test_register_rejects_insufficient_dkg_lead_time():
    admin = Signer.generate()
    dl = InMemoryDataLayer(clock=ManualClock(0))
    # Per-election dkgLeadTime of 500s; config has voting_start=1000 with clock at 600 → only 400s left.
    app = build_admin_app(dl, admin.identity, clock=lambda: 600)
    cfg = _config(admin)
    r = app.test_client().post("/elections", json=_register_body(cfg, admin, dkg_lead_time=500))
    assert r.status_code == 400
    body = r.get_json()
    assert body["error"] == "InsufficientDkgLeadTime"
    assert "too soon for DKG" in body["message"]
    assert "500s" in body["message"]


def test_register_requires_dkg_lead_time_field():
    app, admin, _dl = _app()
    cfg = _config(admin)
    # Omitting dkgLeadTime is a 400 — the gate value must be supplied per-election.
    body = {"config": codecs.enc_config(cfg), "signature": codecs.enc_bytes(admin.sign_register(cfg))}
    r = app.test_client().post("/elections", json=body)
    assert r.status_code == 400
    assert r.get_json()["error"] == "MissingDkgLeadTime"


def test_register_then_cancel():
    app, admin, dl = _app()
    c = app.test_client()
    cfg = _config(admin)
    eid_hex = c.post("/elections", json=_register_body(cfg, admin)).get_json()["electionId"]
    eid = bytes.fromhex(eid_hex.removeprefix("0x"))
    assert dl.get_election(eid).cancelled is False
    # cancel needs the admin's signature over ("cancel", eid)
    good = codecs.enc_bytes(admin.sign("cancel", eid))
    bad = codecs.enc_bytes(Signer.generate().sign("cancel", eid))
    assert c.post(f"/elections/{eid.hex()}/cancel", json={"signature": bad}).status_code == 401
    assert c.post(f"/elections/{eid.hex()}/cancel", json={"signature": good}).status_code == 204
    assert dl.get_election(eid).cancelled is True
