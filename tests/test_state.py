"""Exhaustive coverage of derive_state (DESIGN.md §4.2), including boundaries."""

from __future__ import annotations

import pytest

from geg.core.state import ElectionState, StateFacts, derive_state, is_voting_open

# voting_start=1000, voting_end=2000, tally_deadline=3000 (from env.config defaults)


def _facts(cancelled=False, key=False, result=False):
    return StateFacts(cancelled=cancelled, key_finalized=key, result_published=result)


def test_registered_before_start_no_key(env):
    cfg = env.config()
    assert derive_state(cfg, _facts(), now=500) is ElectionState.REGISTERED


def test_key_ready_before_start(env):
    cfg = env.config()
    assert derive_state(cfg, _facts(key=True), now=500) is ElectionState.KEY_READY


def test_voting_at_start_boundary_inclusive(env):
    cfg = env.config()
    assert derive_state(cfg, _facts(key=True), now=1000) is ElectionState.VOTING


def test_voting_mid_window(env):
    cfg = env.config()
    assert derive_state(cfg, _facts(key=True), now=1500) is ElectionState.VOTING


def test_voting_end_boundary_is_tallying_not_voting(env):
    """Half-open [start, end): exactly voting_end is out of the voting window."""
    cfg = env.config()
    assert derive_state(cfg, _facts(key=True), now=2000) is ElectionState.TALLYING


def test_tallying_before_deadline(env):
    cfg = env.config()
    assert derive_state(cfg, _facts(key=True), now=2500) is ElectionState.TALLYING


def test_dkg_failed_when_no_key_at_start(env):
    cfg = env.config()
    assert derive_state(cfg, _facts(key=False), now=1000) is ElectionState.DKG_FAILED
    assert derive_state(cfg, _facts(key=False), now=1500) is ElectionState.DKG_FAILED


def test_void_at_deadline_without_result(env):
    cfg = env.config()
    assert derive_state(cfg, _facts(key=True), now=3000) is ElectionState.VOID
    assert derive_state(cfg, _facts(key=True), now=5000) is ElectionState.VOID


def test_complete_when_result_published(env):
    cfg = env.config()
    # Complete wins even after the deadline.
    assert derive_state(cfg, _facts(key=True, result=True), now=2500) is ElectionState.COMPLETE
    assert derive_state(cfg, _facts(key=True, result=True), now=9999) is ElectionState.COMPLETE


def test_cancelled_takes_precedence(env):
    cfg = env.config()
    assert derive_state(cfg, _facts(cancelled=True), now=500) is ElectionState.CANCELLED
    # Cancellation only recorded before start, but if present it dominates.
    assert derive_state(cfg, _facts(cancelled=True, key=True), now=500) is ElectionState.CANCELLED


@pytest.mark.parametrize(
    "now,expected",
    [(999, False), (1000, True), (1500, True), (1999, True), (2000, False), (2500, False)],
)
def test_is_voting_open_boundaries(env, now, expected):
    assert is_voting_open(env.config(), now) is expected
