"""End-to-end service flows on the in-memory adapter (DESIGN.md §2, §8).

Drives a full election through the actual services — admin → DKG coordinator →
gateway → tally aggregator → keypers → auditor — plus the security-relevant
negative cases (keyper preconditions, hardening profile, gateway filter, admin
lead-time gate, auditor tamper detection).
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from geg.services import admin, auditor
from geg.services.coordinator import dkg_coordinator as coord
from geg.services import tally_aggregator as agg
from geg.services.gateway import GatewayRejection, submit_ballot
from geg.services.keyper import KeyperRefusal

DKG_LEAD_TIME = 100


def _register_and_dkg(fe):
    admin.register_election(fe.dl, fe.config, fe.admin, clock=fe.clock, dkg_lead_time=DKG_LEAD_TIME)
    ok = coord.ensure_dkg(
        fe.config.election_id, fe.keypers, fe.dl, n=fe.n, t=fe.t,
        clock=fe.clock, deadline=fe.config.voting_start,
    )
    assert ok
    assert fe.dl.get_finalized_key(fe.config.election_id) is not None


# --------------------------------------------------------------------------- #
#  Happy path
# --------------------------------------------------------------------------- #

def test_full_single_choice_election(full_env):
    fe = full_env
    _register_and_dkg(fe)

    # Voting window.
    fe.clock.set(1_500)
    votes = [[3, 0, 0], [0, 3, 0], [0, 3, 0], [0, 0, 3]]
    for i, v in enumerate(votes):
        submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot(v, bytes([i + 1]) * 32), clock=fe.clock)
    assert fe.dl.count_ballots(fe.config.election_id) == 4

    # Tally.
    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.aggregator, fe.keypers, clock=fe.clock)
    assert result is not None
    # candidate totals: cand0=3, cand1=6, cand2=3
    assert list(result.totals) == [3, 6, 3]

    # Auditor confirms everything from public reads.
    report = auditor.audit(fe.dl, fe.config.election_id)
    assert report.ok, report.discrepancies


def test_full_weighted_election(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2), clock=fe.clock)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([0, 3, 0], b"\x02" * 32, weight=5), clock=fe.clock)
    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.aggregator, fe.keypers, clock=fe.clock)
    # [2*3, 5*3, 0] = [6, 15, 0]
    assert list(result.totals) == [6, 15, 0]
    assert auditor.audit(fe.dl, fe.config.election_id).ok


def test_hardened_keypers_full_flow(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([1, 1, 1], b"\x01" * 32), clock=fe.clock)
    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.aggregator, fe.keypers, clock=fe.clock, hardened=True)
    assert list(result.totals) == [1, 1, 1]


# --------------------------------------------------------------------------- #
#  Admin lead-time gate
# --------------------------------------------------------------------------- #

def test_registration_rejected_without_lead_time(full_env):
    fe = full_env
    fe.clock.set(950)  # voting_start=1000, lead time 100 → only 50 left
    with pytest.raises(admin.RegistrationError, match="lead time"):
        admin.register_election(fe.dl, fe.config, fe.admin, clock=fe.clock, dkg_lead_time=DKG_LEAD_TIME)


# --------------------------------------------------------------------------- #
#  Gateway filter + window
# --------------------------------------------------------------------------- #

def test_gateway_rejects_outside_voting_window(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(500)  # before voting_start → not Voting
    with pytest.raises(GatewayRejection, match="voting is not open"):
        submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32), clock=fe.clock)


def test_gateway_filter_rejects_malformed_ballot(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    b = fe.voter_ballot([3, 0, 0], b"\x01" * 32)
    bad_sig = bytearray(b.voter_signature); bad_sig[-1] ^= 1
    b = replace(b, voter_signature=bytes(bad_sig))
    with pytest.raises(GatewayRejection):
        submit_ballot(fe.dl, fe.config.election_id, b, clock=fe.clock)


def test_gateway_filter_off_admits_but_tally_still_excludes(full_env):
    """A compromised/disabled filter can inject an invalid ballot; the tally is
    unaffected because verification is authoritative at tally time (§6.2)."""
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    good = fe.voter_ballot([3, 0, 0], b"\x01" * 32)
    bad = fe.voter_ballot([0, 3, 0], b"\x02" * 32)
    bad_sig = bytearray(bad.voter_signature); bad_sig[-1] ^= 1
    bad = replace(bad, voter_signature=bytes(bad_sig))
    submit_ballot(fe.dl, fe.config.election_id, good, clock=fe.clock)
    submit_ballot(fe.dl, fe.config.election_id, bad, clock=fe.clock, filter_on=False)  # injected
    assert fe.dl.count_ballots(fe.config.election_id) == 2

    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.aggregator, fe.keypers, clock=fe.clock)
    # only the good ballot counts
    assert list(result.totals) == [3, 0, 0]
    agg_artifact = fe.dl.get_aggregate(fe.config.election_id)
    assert agg_artifact.admitted == (0,)
    assert len(agg_artifact.exclusions) == 1


# --------------------------------------------------------------------------- #
#  Keyper preconditions (§8.2) — never trust the trigger
# --------------------------------------------------------------------------- #

def test_keyper_refuses_before_voting_ends(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)  # still Voting
    with pytest.raises(KeyperRefusal, match="not tallying"):
        fe.keypers[0].decrypt_and_submit(fe.config.election_id)


def test_keyper_refuses_without_aggregate(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(2_500)  # Tallying, but no aggregate published yet
    with pytest.raises(KeyperRefusal, match="no aggregate"):
        fe.keypers[0].decrypt_and_submit(fe.config.election_id)


def test_keyper_decryption_is_idempotent(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([1, 1, 1], b"\x01" * 32), clock=fe.clock)
    fe.clock.set(2_500)
    agg.publish_aggregate(fe.dl, fe.config.election_id, fe.aggregator, clock=fe.clock)
    fe.keypers[0].decrypt_and_submit(fe.config.election_id)
    fe.keypers[0].decrypt_and_submit(fe.config.election_id)  # no-op
    mine = [s for s in fe.dl.list_decryption_shares(fe.config.election_id) if s.keyper_index == 1]
    assert len(mine) == 1


# --------------------------------------------------------------------------- #
#  Auditor tamper detection
# --------------------------------------------------------------------------- #

def test_auditor_detects_tampered_result(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([1, 1, 1], b"\x01" * 32), clock=fe.clock)
    fe.clock.set(2_500)
    agg.run_tally(fe.dl, fe.config.election_id, fe.aggregator, fe.keypers, clock=fe.clock)

    # Forge a wrong result directly in storage (simulating a malicious data layer).
    stored = fe.dl._elections[fe.config.election_id]
    stored.result = replace(stored.result, totals=(9, 9, 9))
    report = auditor.audit(fe.dl, fe.config.election_id)
    assert not report.ok
    assert any("totals disagree" in d for d in report.discrepancies)


def test_auditor_detects_tampered_aggregate(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32), clock=fe.clock)
    fe.clock.set(2_500)
    agg.publish_aggregate(fe.dl, fe.config.election_id, fe.aggregator, clock=fe.clock)

    # Tamper: claim no ballots were admitted.
    stored = fe.dl._elections[fe.config.election_id]
    stored.aggregate = replace(stored.aggregate, admitted=())
    report = auditor.audit(fe.dl, fe.config.election_id)
    assert not report.aggregate_ok
    assert any("admitted set differs" in d for d in report.discrepancies)


# --------------------------------------------------------------------------- #
#  Hardening profile (§8.2): defeat the "exclude everyone but Alice" attack
# --------------------------------------------------------------------------- #

def _malicious_isolate_alice(fe):
    """Publish an aggregate that admits only Alice and falsely excludes Bob."""
    from geg.core.admission import AdmittedBallot, StoredBallot
    from geg.core.aggregation import aggregate_points
    from geg.crypto.points import g2_to_compressed
    from geg.envelopes.types import AggregateArtifact, Ciphertext, Exclusion, ExclusionReason

    eid = fe.config.election_id
    stored = list(fe.dl.list_ballots(eid, 0, fe.dl.count_ballots(eid)))
    alice = AdmittedBallot(0, stored[0], stored[0].attestation.weight)
    pts = aggregate_points([alice], fe.config.num_candidates)  # sum over Alice only
    malicious = AggregateArtifact(
        election_id=eid,
        aggregates=tuple(Ciphertext(c1=g2_to_compressed(c1), c2=g2_to_compressed(c2)) for (c1, c2) in pts),
        admitted=(0,),
        exclusions=(Exclusion(sequence_number=1, reason=ExclusionReason.INVALID_PROOF),),  # false reason
        total_admitted_weight=alice.weight,
    )
    fe.dl.publish_aggregate(eid, malicious, fe.aggregator.sign("aggregate", eid))


def test_naive_keyper_decrypts_isolation_attack_but_hardened_refuses(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32), clock=fe.clock)  # Alice
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([0, 3, 0], b"\x02" * 32), clock=fe.clock)  # Bob
    fe.clock.set(2_500)
    _malicious_isolate_alice(fe)

    # A naive keyper trusts the aggregator's published aggregate and would decrypt
    # it (this is the admin/aggregator privacy trust assumption of §3).
    assert fe.keypers[0].decrypt_and_submit(fe.config.election_id) is True

    # A hardened keyper re-verifies the excluded ballot, finds Bob was valid, refuses.
    with pytest.raises(KeyperRefusal, match="excluded but is valid"):
        fe.keypers[1].decrypt_and_submit(fe.config.election_id, hardened=True)


def test_hardened_keyper_refuses_aggregate_sum_mismatch(full_env):
    """Aggregate whose ciphertexts don't match the sum over its own admitted set."""
    from geg.crypto.points import g2_to_compressed
    from geg.core.aggregation import aggregate_points
    from geg.core.admission import AdmittedBallot
    from geg.envelopes.types import AggregateArtifact, Ciphertext

    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32), clock=fe.clock)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([0, 3, 0], b"\x02" * 32), clock=fe.clock)
    fe.clock.set(2_500)

    eid = fe.config.election_id
    stored = list(fe.dl.list_ballots(eid, 0, fe.dl.count_ballots(eid)))
    # admitted set claims both, but ciphertexts are Alice-only → sum mismatch.
    alice = AdmittedBallot(0, stored[0], stored[0].attestation.weight)
    pts = aggregate_points([alice], fe.config.num_candidates)
    malicious = AggregateArtifact(
        election_id=eid,
        aggregates=tuple(Ciphertext(c1=g2_to_compressed(c1), c2=g2_to_compressed(c2)) for (c1, c2) in pts),
        admitted=(0, 1),
        exclusions=(),
        total_admitted_weight=2,
    )
    fe.dl.publish_aggregate(eid, malicious, fe.aggregator.sign("aggregate", eid))
    with pytest.raises(KeyperRefusal, match="does not match published aggregate"):
        fe.keypers[0].decrypt_and_submit(eid, hardened=True)
