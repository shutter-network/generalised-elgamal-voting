"""Ballot admission: happy path, every exclusion reason, duplicate policies, determinism."""

from __future__ import annotations

from dataclasses import replace

from geg.core.admission import StoredBallot, admit
from geg.core.config import DuplicatePolicy
from geg.envelopes.types import Attestation, AttestationScheme, ExclusionReason

P1 = b"\xa1" * 32
P2 = b"\xa2" * 32
P3 = b"\xa3" * 32


def _stored(env, seq, votes, pseudonym, **kw):
    return StoredBallot(sequence_number=seq, envelope=env.ballot(votes, pseudonym, **kw))


def test_all_valid_admitted(env):
    cfg = env.config()
    ballots = [
        _stored(env, 0, [1, 0, 2], P1),
        _stored(env, 1, [0, 3, 0], P2),
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert len(res.admitted) == 2
    assert res.exclusions == ()
    assert res.total_admitted_weight == 2  # weight 1 each


def test_weighted_admission_sums_weights(env):
    cfg = env.config()
    ballots = [
        _stored(env, 0, [1, 0, 2], P1, weight=3),
        _stored(env, 1, [0, 3, 0], P2, weight=5),
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert res.total_admitted_weight == 8
    assert {a.weight for a in res.admitted} == {3, 5}


def test_exclude_wrong_election_malformed(env):
    cfg = env.config()
    ballots = [StoredBallot(0, env.ballot([1, 0, 2], P1, election_id=b"\x99" * 32))]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert res.exclusions[0].reason is ExclusionReason.MALFORMED


def test_exclude_out_of_window(env):
    cfg = env.config()  # window [1000, 2000)
    ballots = [StoredBallot(0, env.ballot([1, 0, 2], P1), submitted_at=2000)]  # at end = out
    res = admit(ballots, cfg, env.mpk_bytes)
    assert res.exclusions[0].reason is ExclusionReason.OUT_OF_WINDOW


def test_in_window_submitted_at_admitted(env):
    cfg = env.config()
    ballots = [StoredBallot(0, env.ballot([1, 0, 2], P1), submitted_at=1500)]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert len(res.admitted) == 1


def test_exclude_bad_attestation_signature(env):
    cfg = env.config()
    b = env.ballot([1, 0, 2], P1)
    bad_sig = bytearray(b.attestation.signature)
    bad_sig[-1] ^= 0x01
    b = replace(b, attestation=replace(b.attestation, signature=bytes(bad_sig)))
    res = admit([StoredBallot(0, b)], cfg, env.mpk_bytes)
    assert res.exclusions[0].reason is ExclusionReason.INVALID_ATTESTATION


def test_admits_a_large_weight_now_that_there_is_no_ceiling(env):
    """The per-election `max_weight` cap is gone, so a large weight is just a weight.

    It used to be excluded as INVALID_ATTESTATION above the ceiling. That ceiling only
    made sense while voting power was clamped; once it is not, the bound had to be set
    at least as high as the largest legitimate holder, at which point it stopped
    constraining anything. Weights are public in every ballot, so a forged one is
    visible to an auditor either way.
    """
    cfg = env.config()
    ballots = [_stored(env, 0, [1, 0, 2], P1, weight=10**9)]
    res = admit(ballots, cfg, env.mpk_bytes)
    assert res.exclusions == ()
    assert res.total_admitted_weight == 10**9



def test_exclude_attestation_not_bound_to_ballot_vk(env):
    """Attestation for a different vk must not admit this ballot."""
    cfg = env.config()
    b1 = env.ballot([1, 0, 2], P1)
    b2 = env.ballot([0, 3, 0], P1)
    # Graft b2's attestation (different vk) onto b1.
    b = replace(b1, attestation=b2.attestation)
    res = admit([StoredBallot(0, b)], cfg, env.mpk_bytes)
    assert res.exclusions[0].reason is ExclusionReason.INVALID_ATTESTATION


def test_exclude_tampered_ciphertext_invalid_proof(env):
    cfg = env.config()
    b1 = env.ballot([1, 0, 2], P1)
    b2 = env.ballot([0, 3, 0], P2)
    cts = list(b1.ciphertexts)
    cts[0] = b2.ciphertexts[0]
    b = replace(b1, ciphertexts=tuple(cts))
    res = admit([StoredBallot(0, b)], cfg, env.mpk_bytes)
    assert res.exclusions[0].reason in (ExclusionReason.INVALID_PROOF, ExclusionReason.INVALID_SIGNATURE)


def test_first_wins_duplicate_policy(env):
    cfg = env.config(duplicate_policy=DuplicatePolicy.FIRST_WINS)
    ballots = [
        _stored(env, 0, [1, 0, 2], P1),
        _stored(env, 1, [0, 3, 0], P1),  # duplicate pseudonym
        _stored(env, 2, [3, 0, 0], P2),
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    admitted_seqs = {a.sequence_number for a in res.admitted}
    assert admitted_seqs == {0, 2}
    dup = [x for x in res.exclusions if x.reason is ExclusionReason.DUPLICATE_PSEUDONYM]
    assert [x.sequence_number for x in dup] == [1]


def test_last_wins_duplicate_policy(env):
    cfg = env.config(duplicate_policy=DuplicatePolicy.LAST_WINS)
    ballots = [
        _stored(env, 0, [1, 0, 2], P1),
        _stored(env, 1, [0, 3, 0], P1),  # duplicate; this one wins
        _stored(env, 2, [3, 0, 0], P2),
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    admitted_seqs = {a.sequence_number for a in res.admitted}
    assert admitted_seqs == {1, 2}
    dup = [x for x in res.exclusions if x.reason is ExclusionReason.DUPLICATE_PSEUDONYM]
    assert [x.sequence_number for x in dup] == [0]


def test_last_wins_orders_by_nonce_not_sequence(env):
    """The winner is the highest attestation nonce, regardless of submission order."""
    cfg = env.config(duplicate_policy=DuplicatePolicy.LAST_WINS)
    ballots = [
        _stored(env, 0, [0, 3, 0], P1, nonce=2),  # genuine re-vote (higher nonce)
        _stored(env, 1, [1, 0, 2], P1, nonce=1),  # earlier vote, submitted LATER
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    admitted_seqs = {a.sequence_number for a in res.admitted}
    assert admitted_seqs == {0}  # the nonce-2 ballot wins even though nonce-1 came later
    dup = [x for x in res.exclusions if x.reason is ExclusionReason.DUPLICATE_PSEUDONYM]
    assert [x.sequence_number for x in dup] == [1]


def test_replayed_old_ballot_never_overrides_revote(env):
    """Replay/reordering defense: re-submitting a voter's OLD ballot at a later sequence
    cannot revert their re-vote — the higher-nonce ballot always wins. Mirrors: vote A
    (nonce 1), re-vote B (nonce 2), attacker replays A verbatim at a later sequence."""
    cfg = env.config(duplicate_policy=DuplicatePolicy.LAST_WINS)
    a = env.ballot([1, 0, 2], P1, nonce=1)   # first vote
    b = env.ballot([0, 3, 0], P1, nonce=2)   # genuine re-vote
    ballots = [
        StoredBallot(0, a),
        StoredBallot(1, b),
        StoredBallot(2, a),  # attacker replays the OLD ballot verbatim, later
    ]
    res = admit(ballots, cfg, env.mpk_bytes)
    admitted = res.admitted
    assert len(admitted) == 1
    assert admitted[0].sequence_number == 1  # the nonce-2 re-vote, not the replayed nonce-1


def test_invalid_ballot_not_counted_as_duplicate(env):
    """A crypto-invalid ballot gets its crypto reason, never DUPLICATE."""
    cfg = env.config(duplicate_policy=DuplicatePolicy.FIRST_WINS)
    good = env.ballot([1, 0, 2], P1)
    bad = env.ballot([0, 3, 0], P1)
    bad_sig = bytearray(bad.voter_signature)
    bad_sig[-1] ^= 0x01
    bad = replace(bad, voter_signature=bytes(bad_sig))
    res = admit([StoredBallot(0, good), StoredBallot(1, bad)], cfg, env.mpk_bytes)
    assert {a.sequence_number for a in res.admitted} == {0}
    assert res.exclusions[0].reason in (ExclusionReason.INVALID_SIGNATURE, ExclusionReason.MALFORMED)


def test_admission_is_deterministic(env):
    cfg = env.config()
    ballots = [_stored(env, 0, [1, 0, 2], P1), _stored(env, 1, [0, 3, 0], P2)]
    r1 = admit(ballots, cfg, env.mpk_bytes)
    r2 = admit(ballots, cfg, env.mpk_bytes)
    assert [a.sequence_number for a in r1.admitted] == [a.sequence_number for a in r2.admitted]
    assert r1.exclusions == r2.exclusions
