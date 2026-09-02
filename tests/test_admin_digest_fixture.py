"""Cross-implementation lock for the admin wallet-signature request digests.

These exact values are also asserted by the admin app's Vitest
(`frontend/apps/admin/src/adminSign.test.ts`), so the browser wallet signs the *same*
digest the Python `verify_register` / `verify_request` recover from. If the config wire
shape or the digest scheme changes, update both sides together.
"""

from __future__ import annotations

import pytest
from eth_utils import keccak

from geg.core import authz
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant

_EXPECTED_REGISTER = "0x8536550a834b1758270a909fdf80fa18a10d08ea391abfb00132d62f586e52e7"
_EXPECTED_CANCEL = "0x565f20982cb67ac495bf11fd0bba3020cab421e17ce0e8ae697d42f8f06ecce3"

_CONFIG = ElectionConfig(
    election_id=b"\x11" * 32,  # bound by the signature (the asserted next id)
    num_candidates=3, budget=3, mode=Mode.EXACT, variant=Variant.A, weighted=True,
    duplicate_policy=DuplicatePolicy.LAST_WINS, voting_start=1000, voting_end=2000,
    threshold=Threshold(t=2, n=3),
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


# --------------------------------------------------------------------------- #
#  request_digest field framing
# --------------------------------------------------------------------------- #
#
# The old encoding was `keccak(op | b"|" | election_id | b"|" | payload)`. With no length
# framing, a field containing the separator could impersonate a field boundary, so two
# different (op, eid, payload) triples hashed equal and shared one signature.

def test_request_digest_is_unambiguous_across_field_boundaries():
    """The exact collision the old `|`-joined encoding produced."""
    a = authz.request_digest("a", b"b", b"c|d")
    b = authz.request_digest("a", b"b|c", b"d")
    assert a != b, "separator-containing fields must not collide"

    # The old scheme's output, shown to be the shared value both used to hash to.
    legacy = keccak(b"a" + b"|" + b"b" + b"|" + b"c|d")
    assert legacy == keccak(b"a" + b"|" + b"b|c" + b"|" + b"d")
    assert a != legacy and b != legacy, "framed digests must not equal the old ambiguous one"


@pytest.mark.parametrize(
    "left,right",
    [
        # Shifting a byte across every boundary must change the digest.
        (("cancel", b"\x01" * 32, b""), ("cance", b"l" + b"\x01" * 32, b"")),
        (("op", b"\x01" * 32, b"\x02"), ("op", b"\x01" * 32 + b"\x02", b"")),
        (("op", b"", b"\x01\x02"), ("op", b"\x01", b"\x02")),
        # Distinct ops over the same election stay distinct (op is bound, not just prefixed).
        (("tally_stall", b"\x09" * 32, b""), ("tally_resume", b"\x09" * 32, b"")),
    ],
)
def test_request_digest_binds_each_field_separately(left, right):
    assert authz.request_digest(*left) != authz.request_digest(*right)


def test_request_digest_is_domain_separated():
    """The tag keeps these digests out of any other keccak namespace in the codebase."""
    op, eid = "cancel", b"\x01" * 32
    unprefixed = keccak(
        len(op.encode()).to_bytes(4, "big") + op.encode()
        + len(eid).to_bytes(4, "big") + eid
        + (0).to_bytes(4, "big")
    )
    assert authz.request_digest(op, eid) != unprefixed
    assert authz.REQUEST_DST == b"GEG-REQUEST-v1"
