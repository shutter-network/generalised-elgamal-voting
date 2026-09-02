"""Weighted aggregation + threshold recovery end-to-end over the deep modules."""

from __future__ import annotations

from geg.core.admission import StoredBallot, admit
from geg.core.aggregation import bsgs_bound, build_aggregate_artifact, recover_result

P1 = b"\xa1" * 32
P2 = b"\xa2" * 32
P3 = b"\xa3" * 32


def _run(env, cfg, ballots):
    res = admit(ballots, cfg, env.mpk_bytes)
    agg = build_aggregate_artifact(cfg, res)
    shares = env.shares_for(agg, keyper_indices=[1, 2])  # t+1 = 2
    result = recover_result(cfg, agg, shares, env.committee_pks, env.threshold_t)
    return res, agg, result


def test_unweighted_tally(env):
    cfg = env.config(weighted=False)
    # votes per candidate summing to budget 3
    ballots = [
        StoredBallot(0, env.ballot([1, 0, 2], P1)),
        StoredBallot(1, env.ballot([0, 3, 0], P2)),
        StoredBallot(2, env.ballot([1, 1, 1], P3)),
    ]
    res, agg, result = _run(env, cfg, ballots)
    assert result is not None
    # candidate totals: [1+0+1, 0+3+1, 2+0+1] = [2, 4, 3]
    assert list(result.totals) == [2, 4, 3]
    assert sum(result.totals) == cfg.budget * len(ballots)


def test_weighted_tally(env):
    cfg = env.config(weighted=True)
    ballots = [
        StoredBallot(0, env.ballot([1, 0, 2], P1, weight=2)),
        StoredBallot(1, env.ballot([0, 3, 0], P2, weight=5)),
    ]
    res, agg, result = _run(env, cfg, ballots)
    assert result is not None
    # [2*1 + 5*0, 2*0 + 5*3, 2*2 + 5*0] = [2, 15, 4]
    assert list(result.totals) == [2, 15, 4]


def test_bsgs_bound_is_derived(env):
    cfg = env.config()
    ballots = [
        StoredBallot(0, env.ballot([1, 0, 2], P1, weight=2)),
        StoredBallot(1, env.ballot([0, 3, 0], P2, weight=5)),
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    agg = build_aggregate_artifact(cfg, res)
    assert agg.total_admitted_weight == 7
    assert bsgs_bound(cfg, agg.total_admitted_weight) == cfg.budget * 7


def test_aggregate_records_admitted_and_exclusions(env):
    from dataclasses import replace

    cfg = env.config()
    good = env.ballot([1, 0, 2], P1)
    bad = env.ballot([0, 3, 0], P2)
    bad_sig = bytearray(bad.voter_signature); bad_sig[-1] ^= 1
    bad = replace(bad, voter_signature=bytes(bad_sig))
    res = admit([StoredBallot(0, good), StoredBallot(1, bad)], cfg, env.mpk_bytes)
    agg = build_aggregate_artifact(cfg, res)
    assert agg.admitted == (0,)
    assert len(agg.exclusions) == 1 and agg.exclusions[0].sequence_number == 1


def test_recovery_fails_with_insufficient_shares(env):
    cfg = env.config()
    ballots = [StoredBallot(0, env.ballot([1, 0, 2], P1))]
    res = admit(ballots, cfg, env.mpk_bytes)
    agg = build_aggregate_artifact(cfg, res)
    only_one = env.shares_for(agg, keyper_indices=[1])  # < t+1
    assert recover_result(cfg, agg, only_one, env.committee_pks, env.threshold_t) is None


def test_recovery_rejects_forged_share_then_uses_valid(env):
    """A share with a bad DLEQ is skipped; recovery still succeeds via valid ones."""
    from dataclasses import replace

    cfg = env.config()
    ballots = [StoredBallot(0, env.ballot([3, 0, 0], P1))]
    res = admit(ballots, cfg, env.mpk_bytes)
    agg = build_aggregate_artifact(cfg, res)
    shares = env.shares_for(agg, keyper_indices=[1, 2, 3])  # 3 shares, need 2
    # Corrupt keyper 1's proof on candidate 0.
    s0 = shares[0]
    bad_entries = list(s0.entries)
    bad_proof = bytearray(bad_entries[0].proof); bad_proof[0] ^= 0x01
    bad_entries[0] = replace(bad_entries[0], proof=bytes(bad_proof))
    shares[0] = replace(s0, entries=tuple(bad_entries))
    result = recover_result(cfg, agg, shares, env.committee_pks, env.threshold_t)
    assert result is not None
    assert list(result.totals) == [3, 0, 0]


def test_any_t_plus_1_keyper_subset_agrees(env):
    cfg = env.config()
    ballots = [StoredBallot(0, env.ballot([1, 1, 1], P1))]
    res = admit(ballots, cfg, env.mpk_bytes)
    agg = build_aggregate_artifact(cfg, res)
    totals = set()
    for subset in ([1, 2], [1, 3], [2, 3]):
        shares = env.shares_for(agg, subset)
        r = recover_result(cfg, agg, shares, env.committee_pks, env.threshold_t)
        totals.add(tuple(r.totals))
    assert totals == {(1, 1, 1)}


# --------------------------------------------------------------------------- #
#  The baby-step table is built once per election, not once per candidate
# --------------------------------------------------------------------------- #

def test_recover_result_builds_one_baby_step_table_for_the_whole_election(env, monkeypatch):
    """Asserted by counting builds, not by timing.

    The table depends only on the bound, so an election with ℓ candidates needs
    exactly one. Building it per candidate — which `recover_result` used to do —
    costs ℓ times the work for an identical answer, and at the sizes a real
    election reaches that is minutes rather than seconds
    (``docs/COORDINATOR_SIZING.md``). A timing assertion would be flaky and would
    not say *why* it regressed; counting says exactly that.
    """
    from geg.core import aggregation
    from geg.crypto import recovery

    builds: list[int] = []
    real_build = recovery.build_baby_step_table

    def counting_build(max_val):
        builds.append(max_val)
        return real_build(max_val)

    monkeypatch.setattr(aggregation, "build_baby_step_table", counting_build)

    cfg = env.config(weighted=True)
    ballots = [
        StoredBallot(0, env.ballot([1, 0, 2], P1, weight=2)),
        StoredBallot(1, env.ballot([0, 3, 0], P2, weight=5)),
    ]
    _, _, result = _run(env, cfg, ballots)

    assert result is not None
    assert cfg.num_candidates > 1, (
        "a single-candidate election could not tell one build from ℓ builds"
    )
    assert len(builds) == 1, (
        f"expected one table build for {cfg.num_candidates} candidates, got {len(builds)}"
    )


def test_recover_result_refuses_a_bound_over_the_deployment_ceiling(env):
    """Reports rather than dying in the allocator.

    Without this, an over-sized election spends minutes building a table and then
    gets OOM-killed — indistinguishable from a crash, and an operator cannot tell
    that more memory is exactly the fix. The check runs before any share is
    verified because the bound follows from public data alone.
    """
    import pytest

    from geg.core.aggregation import TallyInfeasible, bsgs_bound

    cfg = env.config(weighted=True)
    ballots = [
        StoredBallot(0, env.ballot([1, 0, 2], P1, weight=2)),
        StoredBallot(1, env.ballot([0, 3, 0], P2, weight=5)),
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    agg = build_aggregate_artifact(cfg, res)
    shares = env.shares_for(agg, keyper_indices=[1, 2])
    bound = bsgs_bound(cfg, agg.total_admitted_weight)

    with pytest.raises(TallyInfeasible, match="exceeds this deployment"):
        recover_result(
            cfg, agg, shares, env.committee_pks, env.threshold_t,
            solver_ceiling=bound - 1,
        )

    # Exactly at the ceiling is feasible, not refused.
    ok = recover_result(
        cfg, agg, shares, env.committee_pks, env.threshold_t, solver_ceiling=bound
    )
    assert ok is not None

    # Omitted means unchecked — what the conformance vectors and tests rely on.
    assert recover_result(cfg, agg, shares, env.committee_pks, env.threshold_t) is not None


# --------------------------------------------------------------------------- #
#  Weight scaling
# --------------------------------------------------------------------------- #

def test_scaled_weight_is_integer_half_up_at_the_boundary():
    """Half-up, and integer-only — the cross-language landmine.

    Python's `round` is half-to-even and JavaScript's `Math.round` is half-up, so a
    float implementation would put geg and the SDK on different aggregates at exactly
    `.5`. That surfaces as an honest committee appearing to publish a false
    aggregate, with nothing in the error pointing at rounding. The SDK pins the same
    boundary; a divergence must fail on both sides, not silently on neither.
    """
    from geg.core.aggregation import scaled_weight

    # w/s == .5 exactly must round *up*, where Python's round() would give 0 and 2.
    assert scaled_weight(1, 2) == 1
    assert scaled_weight(3, 2) == 2
    assert scaled_weight(5, 2) == 3
    # Below the halfway point still floors to zero.
    assert scaled_weight(1, 4) == 0
    assert scaled_weight(2, 4) == 1
    # scale 1 is the identity — the expected path for essentially every election.
    for w in (0, 1, 7, 10**18):
        assert scaled_weight(w, 1) == w


def test_scaled_election_tallies_in_units_of_scale(env):
    """A scaled election counts proportionally, not truncated at the top."""
    from geg.core.aggregation import bsgs_bound

    cfg = env.config(weighted=True, scale=4)
    ballots = [
        StoredBallot(0, env.ballot([1, 0, 2], P1, weight=8)),    # → 2
        StoredBallot(1, env.ballot([0, 3, 0], P2, weight=10)),   # → 3 (half-up)
        StoredBallot(2, env.ballot([1, 1, 1], P3, weight=2)),    # → 1 (half-up from .5)
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    agg = build_aggregate_artifact(cfg, res)

    # Raw total is turnout in token units; scaled total is what the aggregate used.
    assert agg.total_admitted_weight == 20
    assert agg.total_scaled_weight == 6

    shares = env.shares_for(agg, keyper_indices=[1, 2])
    result = recover_result(cfg, agg, shares, env.committee_pks, env.threshold_t)
    assert result is not None
    # candidate totals with scaled weights 2, 3, 1:
    #   [1*2 + 0*3 + 1*1, 0*2 + 3*3 + 1*1, 2*2 + 0*3 + 1*1] = [3, 10, 5]
    assert list(result.totals) == [3, 10, 5]
    # exact mode: totals sum to budget x Σ scaled, not budget x Σ raw
    assert sum(result.totals) == cfg.budget * agg.total_scaled_weight
    assert result.bsgs_bound == bsgs_bound(cfg, agg.total_scaled_weight)


def test_ballot_scaling_to_zero_is_admitted_and_contributes_nothing(env):
    """Admitted, in no exclusion list, and worth nothing.

    The honest outcome of the O-3 decision: the voter is told before signing, the
    ballot is recorded, and the tally simply does not move. It must not appear as an
    exclusion — that would say the committee rejected it, which is a different and
    false claim.
    """
    cfg = env.config(weighted=True, scale=100)
    ballots = [
        StoredBallot(0, env.ballot([3, 0, 0], P1, weight=200)),  # → 2
        StoredBallot(1, env.ballot([0, 3, 0], P2, weight=10)),   # → 0, dust at this scale
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    agg = build_aggregate_artifact(cfg, res)

    assert set(agg.admitted) == {0, 1}, "the zero-scaled ballot is still admitted"
    assert agg.exclusions == (), "and is not an exclusion"
    assert agg.total_scaled_weight == 2

    shares = env.shares_for(agg, keyper_indices=[1, 2])
    result = recover_result(cfg, agg, shares, env.committee_pks, env.threshold_t)
    assert list(result.totals) == [6, 0, 0], "P2's ballot moved nothing"


def test_scale_one_is_byte_identical_to_an_unscaled_election(env):
    """The regression that matters most: existing elections must not shift.

    `scale=1` has to reproduce the pre-scaling aggregate exactly — same ciphertexts,
    same totals, same bound — or shipping this changes results for every space that
    never asked for scaling.
    """
    ballots = [
        StoredBallot(0, env.ballot([1, 0, 2], P1, weight=2)),
        StoredBallot(1, env.ballot([0, 3, 0], P2, weight=5)),
    ]
    default_cfg = env.config(weighted=True)
    explicit_cfg = env.config(weighted=True, scale=1)

    a = build_aggregate_artifact(default_cfg, admit(ballots, default_cfg, env.mpk_bytes))
    b = build_aggregate_artifact(explicit_cfg, admit(ballots, explicit_cfg, env.mpk_bytes))
    assert a == b
    assert a.total_scaled_weight == a.total_admitted_weight == 7
