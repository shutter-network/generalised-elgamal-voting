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
    cfg = env.config(weighted=False, max_weight=1)
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
    cfg = env.config(weighted=True, max_weight=10)
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
