"""Cross-implementation lock for the admin (model B) request digests.

These exact values are also asserted by the admin app's Vitest
(`frontend/apps/admin/src/adminSign.test.ts`), so the browser wallet signs the *same*
digest the Python `verify_register` / `verify_request` recover from. If the config wire
shape or the digest scheme changes, update both sides together.
"""

from __future__ import annotations

from geg.core import authz
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant

_EXPECTED_REGISTER = "0x733c8ed677fc41ea3ba2dca024dc1ee1c9ed1c0acda77294c8b912f651c7da28"
_EXPECTED_CANCEL = "0x2fe6f4c5c76a0413ccc9bd1b4b11bfc872c0c6c747f4477ff0c7033d69410669"

_CONFIG = ElectionConfig(
    election_id=b"\x11" * 32,  # non-zero: proves register_digest zeroes it
    num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A, weighted=True, max_weight=10,
    duplicate_policy=DuplicatePolicy.LAST_WINS, voting_start=1000, voting_end=2000,
    threshold=Threshold(t=1, n=3),
    keypers=(KeyperIdentity(signing_key=bytes.fromhex("aa" * 20), url="http://k1:8101"),
             KeyperIdentity(signing_key=bytes.fromhex("bb" * 20), url="http://k2:8102"),
             KeyperIdentity(signing_key=bytes.fromhex("cc" * 20), url="http://k3:8103")),
    eligibility_key=bytes.fromhex("e1" * 48), result_publisher_key=bytes.fromhex("dd" * 20),
    gateway_keys=(bytes.fromhex("ee" * 20),), admin_key=bytes.fromhex("ab" * 20), protocol_version="v1",
)


def test_register_digest_fixture():
    assert "0x" + authz.register_digest(_CONFIG).hex() == _EXPECTED_REGISTER


def test_cancel_digest_fixture():
    eid = (7).to_bytes(32, "big")
    assert "0x" + authz.request_digest("cancel", eid).hex() == _EXPECTED_CANCEL
