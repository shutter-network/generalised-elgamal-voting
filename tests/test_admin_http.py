"""Admin HTTP service: register/cancel over HTTP, admin-only (bearer token).

Auth model A (the service holds ADMIN_SIGNING_KEY; endpoints gated by a fail-closed
bearer token). Driven over the in-memory data layer via the Flask test client.
"""

from __future__ import annotations

from geg.adapters.memory import InMemoryDataLayer
from geg.core.authz import Signer
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.envelopes import codecs
from geg.services.admin import build_admin_app

from conftest import ManualClock

TOKEN = "s3cret-admin-token"


def _config(admin: Signer) -> ElectionConfig:
    keypers = [Signer.generate() for _ in range(3)]
    return ElectionConfig(
        election_id=b"\x00" * 32, num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A,
        weighted=True, max_weight=10, duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=1_000, voting_end=2_000, tally_deadline=3_000, threshold=Threshold(t=1, n=3),
        keypers=tuple(KeyperIdentity(signing_key=keypers[i].identity, url=f"http://keyper{i+1}:8100")
                      for i in range(3)),
        eligibility_key=b"\xe1" * 48, result_publisher_key=Signer.generate().identity,
        gateway_keys=(Signer.generate().identity,), admin_key=admin.identity, protocol_version="v1",
    )


def _app(api_token):
    admin = Signer.generate()
    dl = InMemoryDataLayer(clock=ManualClock(0))
    app = build_admin_app(dl, admin, clock=lambda: 0, dkg_lead_time=0, api_token=api_token)
    return app, admin, dl


def _body(cfg):
    return {"config": codecs.enc_config(cfg)}


def test_health_is_open():
    app, _admin, _dl = _app(TOKEN)
    assert app.test_client().get("/health").status_code == 200


def test_register_requires_token():
    app, admin, _dl = _app(TOKEN)
    c = app.test_client()
    body = _body(_config(admin))
    assert c.post("/elections", json=body).status_code == 401                      # missing
    assert c.post("/elections", json=body, headers={"Authorization": "Bearer nope"}).status_code == 401
    r = c.post("/elections", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200
    assert r.get_json()["electionId"] == "0x" + (1).to_bytes(32, "big").hex()       # registry-assigned id 1


def test_failclosed_without_configured_token():
    app, admin, _dl = _app(None)  # no ADMIN_API_TOKEN
    r = app.test_client().post("/elections", json=_body(_config(admin)),
                               headers={"Authorization": "Bearer anything"})
    assert r.status_code == 503


def test_register_then_cancel():
    app, admin, dl = _app(TOKEN)
    c = app.test_client()
    hdr = {"Authorization": f"Bearer {TOKEN}"}
    eid_hex = c.post("/elections", json=_body(_config(admin)), headers=hdr).get_json()["electionId"]
    eid = bytes.fromhex(eid_hex.removeprefix("0x"))
    assert dl.get_election(eid).cancelled is False
    assert c.post(f"/elections/{eid.hex()}/cancel", headers=hdr).status_code == 204
    assert dl.get_election(eid).cancelled is True


def test_register_rejects_admin_key_mismatch():
    app, _admin, _dl = _app(TOKEN)
    other = Signer.generate()  # config.admin_key != the service's admin identity
    r = app.test_client().post("/elections", json=_body(_config(other)),
                               headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 400  # RegistrationError
