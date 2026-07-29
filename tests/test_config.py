"""Validation tests for ElectionConfig (DESIGN.md §4.1) and its enums."""

from __future__ import annotations

import pytest

from geg.core.config import (
    DuplicatePolicy,
    ElectionConfig,
    KeyperIdentity,
    Mode,
    Threshold,
    Variant,
)


def _keypers(n: int) -> tuple[KeyperIdentity, ...]:
    return tuple(
        KeyperIdentity(signing_key=bytes([i]) * 20, endpoint=f"https://keyper{i}.example")
        for i in range(n)
    )


def make_config(**overrides) -> ElectionConfig:
    base = dict(
        election_id=b"\x11" * 32,
        num_candidates=3,
        budget=1,
        mode=Mode.EXACT,
        variant=Variant.A,
        weighted=False,
        max_weight=1,
        duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=1_000,
        voting_end=2_000,
        tally_deadline=3_000,
        threshold=Threshold(t=1, n=3),
        keypers=_keypers(3),
        eligibility_key=b"\xe1" * 48,
        result_publisher_key=b"\xa1" * 20,
        gateway_keys=(b"\x91" * 20,),
        admin_key=b"\xad" * 20,
        protocol_version="SHUTTER-VOTE-v1",
    )
    base.update(overrides)
    return ElectionConfig(**base)


def test_valid_config_constructs():
    cfg = make_config()
    assert cfg.threshold.t == 1 and cfg.threshold.n == 3
    assert len(cfg.keypers) == 3


def test_conformance_level_1_defaults():
    """Level 1 = variant A / exact / weighted-capable (DESIGN.md §6.1)."""
    cfg = make_config(weighted=True, max_weight=100)
    assert (cfg.variant, cfg.mode, cfg.weighted) == (Variant.A, Mode.EXACT, True)


@pytest.mark.parametrize(
    "overrides,match",
    [
        (dict(num_candidates=0), "num_candidates"),
        (dict(budget=0), "budget"),
        (dict(max_weight=0), "max_weight"),
        (dict(weighted=False, max_weight=5), "unweighted"),
        (dict(voting_start=2_000, voting_end=2_000), "voting_end must be after"),
        (dict(tally_deadline=1_500), "tally_deadline"),
        (dict(threshold=Threshold(t=1, n=3), keypers=_keypers(2)), "expected 3 keypers"),
    ],
)
def test_invalid_config_rejected(overrides, match):
    with pytest.raises(ValueError, match=match):
        make_config(**overrides)


@pytest.mark.parametrize(
    "t,n",
    [(3, 3), (5, 3), (-1, 3)],
)
def test_invalid_threshold_rejected(t, n):
    with pytest.raises(ValueError):
        Threshold(t=t, n=n)


def test_threshold_t_plus_one_of_n():
    """(t, n): any t+1 of n can decrypt; t < n required (DESIGN.md §4.1)."""
    th = Threshold(t=1, n=3)
    assert th.t + 1 == 2 and th.n == 3
