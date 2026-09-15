"""Two artifacts each reaching the keyper quorum must be refused, not silently resolved
by iteration order.

The old code returned the *first* group it happened to iterate that met the count. The
memory adapter iterates submission order and the DB adapter iterates whatever order the
query returns, so the same set of submissions could finalize a different key on the two
backends — the cross-backend divergence the conformance suite exists to prevent.

Reachability: two disjoint quorums must fit in the committee, i.e. `n >= 2t`, which is the
same as `t <= n/2`. `Threshold` now **rejects** any non-majority quorum, so no legal config
can reach this state at all and the guard below is pure defence in depth — it still matters
because a config can arrive from outside Python validation (read back from a contract, a
future adapter, a hand-built fixture), and because the cost of the check is one comparison.

These tests therefore construct a 2-of-4 committee *deliberately*, bypassing validation via
`object.__setattr__` on the frozen `Threshold`. That is the point: the scenario is
unreachable by construction now, and the guard must still hold if it ever is reached.
"""

from __future__ import annotations

import os

import pytest

from geg.adapters.memory import InMemoryDataLayer
from geg.core import write_auth
from geg.core.authz import Signer
from geg.core.config import (
    DuplicatePolicy,
    ElectionConfig,
    KeyperIdentity,
    Mode,
    Threshold,
    Variant,
)
from geg.envelopes.types import AggregateArtifact, Ciphertext
from geg.ports.data_layer import QuorumConflictError

from conftest import ManualClock

ELECTION_ID = (1).to_bytes(32, "big")
N, T = 4, 2  # n >= 2t, so two disjoint quorums of 2 can both form


def _non_majority_threshold() -> Threshold:
    """A 2-of-4 quorum, which `Threshold` refuses to build directly (t must be > n/2).

    Constructed legally as 3-of-4 and then forced down to 2, so these tests can exercise
    the conflict guard on a committee shape that validation now prevents.
    """
    th = Threshold(t=3, n=N)                  # legal majority
    object.__setattr__(th, "t", T)            # ...then force the non-majority quorum
    assert th.t * 2 <= th.n                   # two disjoint quorums of 2 now fit
    return th

KEY_A = (bytes([0xA0]) * 96, [bytes([0xA1 + i]) * 96 for i in range(N)])
KEY_B = (bytes([0xB0]) * 96, [bytes([0xB1 + i]) * 96 for i in range(N)])


class World:
    def __init__(self):
        self.clock = ManualClock(0)
        self.dl = InMemoryDataLayer(clock=self.clock)
        self.admin, self.rp, self.gw = Signer.generate(), Signer.generate(), Signer.generate()
        self.keypers = [Signer.generate() for _ in range(N)]
        self.config = ElectionConfig(
            election_id=ELECTION_ID, num_candidates=3, budget=3, mode=Mode.EXACT,
            variant=Variant.A, weighted=False,
            duplicate_policy=DuplicatePolicy.LAST_WINS, voting_start=1000, voting_end=2000,
            threshold=_non_majority_threshold(),
            keypers=tuple(KeyperIdentity(signing_key=k.identity, url="") for k in self.keypers),
            eligibility_key=b"\xe1" * 48, result_publisher_key=self.rp.identity,
            gateway_keys=(self.gw.identity,), admin_key=self.admin.identity,
            protocol_version="v1",
        )
        self.dl.register_election(self.config, self.admin.sign_register(self.config))

    def submit_key(self, keyper_index: int, key):
        pk, committee = key
        sig = write_auth.sign_dkg_result(self.keypers[keyper_index - 1].private_key, ELECTION_ID, pk, committee)
        self.dl.submit_dkg_result(ELECTION_ID, pk, committee, sig)

    def aggregate(self, marker: int) -> AggregateArtifact:
        return AggregateArtifact(
            election_id=ELECTION_ID,
            aggregates=tuple(Ciphertext(c1=bytes([marker]) * 96, c2=bytes([marker + 1]) * 96) for _ in range(3)),
            admitted=(), exclusions=(), total_admitted_weight=0,
        )

    def submit_aggregate(self, keyper_index: int, agg):
        sig = write_auth.sign_aggregate(self.keypers[keyper_index - 1].private_key, ELECTION_ID, agg)
        self.dl.submit_aggregate(ELECTION_ID, agg, sig)


@pytest.fixture
def w():
    return World()


# --- DKG result ------------------------------------------------------------- #

def test_single_quorum_still_finalizes_normally(w):
    """Guard against the check being over-eager: one quorum is the healthy case."""
    w.submit_key(1, KEY_A)
    assert w.dl.get_finalized_key(ELECTION_ID) is None      # 1 < quorum
    w.submit_key(2, KEY_A)
    fk = w.dl.get_finalized_key(ELECTION_ID)
    assert fk is not None and fk.pk_election == KEY_A[0]
    # A third keyper agreeing changes nothing.
    w.submit_key(3, KEY_A)
    assert w.dl.get_finalized_key(ELECTION_ID).pk_election == KEY_A[0]


def test_a_minority_disagreeing_does_not_conflict(w):
    """Below-quorum divergence is normal and must not raise: 2 for A, 1 for B."""
    w.submit_key(1, KEY_A)
    w.submit_key(2, KEY_A)
    w.submit_key(3, KEY_B)
    assert w.dl.get_finalized_key(ELECTION_ID).pk_election == KEY_A[0]


def test_two_finalized_dkg_groups_raise_instead_of_picking_one(w):
    w.submit_key(1, KEY_A)
    w.submit_key(2, KEY_A)
    w.submit_key(3, KEY_B)
    w.submit_key(4, KEY_B)          # now A and B each have the quorum of 2
    with pytest.raises(QuorumConflictError) as ei:
        w.dl.get_finalized_key(ELECTION_ID)
    msg = str(ei.value)
    assert "dkg result" in msg and "quorum of 2" in msg
    assert "[1, 2]" in msg and "[3, 4]" in msg, f"both groups should be named: {msg}"


def test_conflict_is_order_independent(w):
    """The bug's signature was order dependence — the *same* submissions in a different
    order used to yield a different winner. Now both orders raise identically."""
    for order in ([1, 2, 3, 4], [3, 4, 1, 2]):
        world = World()
        for i in order:
            world.submit_key(i, KEY_A if i in (1, 2) else KEY_B)
        with pytest.raises(QuorumConflictError):
            world.dl.get_finalized_key(ELECTION_ID)


# --- aggregate -------------------------------------------------------------- #

def test_aggregate_freeze_structurally_prevents_a_second_quorum(w):
    """The aggregate path cannot reach a conflict through the public API, and this pins
    why: `submit_aggregate` refuses any further submission once a quorum has frozen one.

    So of the two artifacts named in the finding, only the DKG result is actually reachable — the
    DKG path is append-only per keyper with **no** quorum freeze (every keyper may submit
    even after the count is met), while the aggregate path closes at the quorum. The
    uniqueness check still guards `get_aggregate` as defence in depth, since the freeze is
    an invariant of this adapter rather than of the port contract.
    """
    from geg.ports.data_layer import ImmutabilityError

    w.clock.set(2_500)
    agg_a, agg_b = w.aggregate(0x11), w.aggregate(0x33)
    w.submit_aggregate(1, agg_a)
    w.submit_aggregate(3, agg_b)          # below quorum: divergence is tolerated
    w.submit_aggregate(2, agg_a)          # A reaches the quorum of 2 → frozen
    assert w.dl.get_aggregate(ELECTION_ID) == agg_a
    with pytest.raises(ImmutabilityError, match="already finalized"):
        w.submit_aggregate(4, agg_b)      # B can never reach 2
    assert w.dl.get_aggregate(ELECTION_ID) == agg_a


# --- the resolver itself ----------------------------------------------------- #
#
# Unit-level, so the aggregate-shaped call is covered even though the adapter's freeze
# stops that state arising through the API.

def test_resolve_unique_returns_none_below_quorum():
    from geg.core.quorum import resolve_unique
    groups = [("A", {1}), ("B", {2})]
    assert resolve_unique(groups, 2, artifact="aggregate", election_id=ELECTION_ID) is None


def test_resolve_unique_returns_the_single_winner():
    from geg.core.quorum import resolve_unique
    groups = [("A", {1, 2}), ("B", {3})]
    assert resolve_unique(groups, 2, artifact="aggregate", election_id=ELECTION_ID) == "A"


def test_resolve_unique_raises_on_two_winners_regardless_of_order():
    from geg.core.quorum import resolve_unique
    for groups in ([("A", {1, 2}), ("B", {3, 4})], [("B", {3, 4}), ("A", {1, 2})]):
        with pytest.raises(QuorumConflictError, match="quorum of 2"):
            resolve_unique(groups, 2, artifact="aggregate", election_id=ELECTION_ID)


def test_resolve_unique_raises_on_three_winners():
    from geg.core.quorum import resolve_unique
    groups = [("A", {1, 2}), ("B", {3, 4}), ("C", {5, 6})]
    with pytest.raises(QuorumConflictError, match="3 distinct artifacts"):
        resolve_unique(groups, 2, artifact="dkg result", election_id=ELECTION_ID)


# --- containment: one conflicted election must not affect the others --------- #

def _register(dl, admin, rp, gw, keypers, eid_int):
    cfg = ElectionConfig(
        election_id=eid_int.to_bytes(32, "big"), num_candidates=3, budget=3, mode=Mode.EXACT,
        variant=Variant.A, weighted=False,
        duplicate_policy=DuplicatePolicy.LAST_WINS, voting_start=1000, voting_end=2000,
        threshold=_non_majority_threshold(),
        keypers=tuple(KeyperIdentity(signing_key=k.identity, url="") for k in keypers),
        eligibility_key=b"\xe1" * 48, result_publisher_key=rp.identity,
        gateway_keys=(gw.identity,), admin_key=admin.identity, protocol_version="v1",
    )
    return dl.register_election(cfg, admin.sign_register(cfg)), cfg


def test_a_conflicted_election_does_not_break_the_others():
    """A split committee must fail *that election only* — the listing and every other
    election stay readable, and the HTTP surface reports 409 rather than a 500."""
    from geg.services.api.api import build_api_app

    clock = ManualClock(0)
    dl = InMemoryDataLayer(clock=clock)
    admin, rp, gw = Signer.generate(), Signer.generate(), Signer.generate()
    keypers = [Signer.generate() for _ in range(N)]

    bad_eid, bad_cfg = _register(dl, admin, rp, gw, keypers, 1)
    good_eid, good_cfg = _register(dl, admin, rp, gw, keypers, 2)

    def submit(eid, keyper_index, key):
        pk, committee = key
        sig = write_auth.sign_dkg_result(keypers[keyper_index - 1].private_key, eid, pk, committee)
        dl.submit_dkg_result(eid, pk, committee, sig)

    for i, key in ((1, KEY_A), (2, KEY_A), (3, KEY_B), (4, KEY_B)):
        submit(bad_eid, i, key)          # election 1: split committee
    for i in (1, 2):
        submit(good_eid, i, KEY_A)       # election 2: healthy

    # The healthy election is entirely unaffected, read directly...
    assert dl.get_finalized_key(good_eid).pk_election == KEY_A[0]
    assert dl.get_election(good_eid).finalized_key is not None
    with pytest.raises(QuorumConflictError):
        dl.get_election(bad_eid)

    # ...and over HTTP, where the listing must still enumerate both.
    client = build_api_app(dl).test_client()
    listing = client.get("/elections")
    assert listing.status_code == 200
    assert sorted(listing.get_json()["electionIds"]) == [1, 2]

    assert client.get("/elections/2").status_code == 200
    conflicted = client.get("/elections/1")
    assert conflicted.status_code == 409, conflicted.get_data(as_text=True)
    assert conflicted.get_json()["error"] == "QuorumConflictError"


# --- the majority rule is what makes this unreachable ------------------------ #

@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 9, 12])
def test_every_legal_committee_admits_only_one_quorum(n):
    """The structural guarantee behind the majority rule: for every quorum `Threshold`
    accepts, two disjoint quorums cannot fit — so a conflict is impossible by arithmetic,
    not by luck. This is the invariant that demotes the guard above to defence in depth."""
    legal = []
    for t in range(1, n + 1):
        try:
            legal.append(Threshold(t=t, n=n).t)
        except ValueError:
            pass
    assert legal, f"n={n} must admit at least one quorum"
    for t in legal:
        assert 2 * t > n, f"{t}-of-{n} was accepted but two disjoint quorums fit"
    assert min(legal) == n // 2 + 1, f"n={n}: minimum majority should be {n // 2 + 1}"


def test_the_conflict_shape_is_rejected_at_config_time():
    """The 2-of-4 committee these tests force is refused by the real constructor."""
    with pytest.raises(ValueError, match="majority"):
        Threshold(t=T, n=N)
