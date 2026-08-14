"""End-to-end service flows on the in-memory adapter.

Drives a full election through the actual services — admin → coordinator (DKG +
tally) → gateway → keypers → auditor — plus the security-relevant negative cases
(keyper preconditions, gateway filter, admin lead-time gate, auditor tamper
detection).
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from geg.core import write_auth
from geg.envelopes.types import ExclusionReason, StoredBallot
from geg.ports.data_layer import VotingWindowError
from geg.services import admin, auditor
from geg.services.coordinator import dkg_coordinator as coord
from geg.services import tally_aggregator as agg
from geg.services.gateway import GatewayRejection, submit_ballot
from geg.services.keyper import KeyperRefusal

DKG_LEAD_TIME = 100


def _register_and_dkg(fe):
    admin.register_election(fe.dl, fe.config, fe.admin.sign_register(fe.config),
                            admin_identity=fe.admin.identity, clock=fe.clock, dkg_lead_time=DKG_LEAD_TIME)
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
        submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot(v, bytes([i + 1]) * 32), clock=fe.clock, gateway_signer=fe.gateway)
    assert fe.dl.count_ballots(fe.config.election_id) == 4

    # Tally.
    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)
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
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2), clock=fe.clock, gateway_signer=fe.gateway)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([0, 3, 0], b"\x02" * 32, weight=5), clock=fe.clock, gateway_signer=fe.gateway)
    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)
    # [2*3, 5*3, 0] = [6, 15, 0]
    assert list(result.totals) == [6, 15, 0]
    assert auditor.audit(fe.dl, fe.config.election_id).ok


# --------------------------------------------------------------------------- #
#  Admin lead-time gate
# --------------------------------------------------------------------------- #

def test_registration_rejected_without_lead_time(full_env):
    fe = full_env
    fe.clock.set(950)  # voting_start=1000, lead time 100 → only 50 left
    with pytest.raises(admin.RegistrationError, match="too soon for DKG"):
        admin.register_election(fe.dl, fe.config, fe.admin.sign_register(fe.config),
                            admin_identity=fe.admin.identity, clock=fe.clock, dkg_lead_time=DKG_LEAD_TIME)


# --------------------------------------------------------------------------- #
#  Gateway filter + window
# --------------------------------------------------------------------------- #

def test_gateway_rejects_outside_voting_window(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(500)  # before voting_start → not Voting
    with pytest.raises(GatewayRejection, match="voting is not open"):
        submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32), clock=fe.clock, gateway_signer=fe.gateway)


def test_gateway_filter_rejects_malformed_ballot(full_env):
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    b = fe.voter_ballot([3, 0, 0], b"\x01" * 32)
    bad_sig = bytearray(b.voter_signature); bad_sig[-1] ^= 1
    b = replace(b, voter_signature=bytes(bad_sig))
    with pytest.raises(GatewayRejection):
        submit_ballot(fe.dl, fe.config.election_id, b, clock=fe.clock, gateway_signer=fe.gateway)


def test_gateway_filter_off_admits_but_tally_still_excludes(full_env):
    """A compromised/disabled filter can inject an invalid ballot; the tally is
    unaffected because verification is authoritative at tally time."""
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    good = fe.voter_ballot([3, 0, 0], b"\x01" * 32)
    bad = fe.voter_ballot([0, 3, 0], b"\x02" * 32)
    bad_sig = bytearray(bad.voter_signature); bad_sig[-1] ^= 1
    bad = replace(bad, voter_signature=bytes(bad_sig))
    submit_ballot(fe.dl, fe.config.election_id, good, clock=fe.clock, gateway_signer=fe.gateway)
    submit_ballot(fe.dl, fe.config.election_id, bad, clock=fe.clock, gateway_signer=fe.gateway, filter_on=False)  # injected
    assert fe.dl.count_ballots(fe.config.election_id) == 2

    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)
    # only the good ballot counts
    assert list(result.totals) == [3, 0, 0]
    agg_artifact = fe.dl.get_aggregate(fe.config.election_id)
    assert agg_artifact.admitted == (0,)
    assert len(agg_artifact.exclusions) == 1


def test_data_layer_rejects_ballot_outside_voting_window(full_env):
    """Prevention half: the storage layer itself refuses an out-of-window ballot,
    so the bypassable gateway is no longer the only thing standing between a late
    submission and the tally. Parity with the chain contract's VotingClosed revert."""
    fe = full_env
    _register_and_dkg(fe)
    late = fe.voter_ballot([0, 3, 0], b"\x02" * 32)
    # Authorized as the registered gateway, so what is under test is the WINDOW gate and
    # not the gateway writer check that now precedes it.
    sig = write_auth.sign_ballot(fe.gateway.private_key, fe.config.election_id, late)

    fe.clock.set(2_500)  # past voting_end
    with pytest.raises(VotingWindowError):
        fe.dl.submit_ballot(fe.config.election_id, late, sig)

    fe.clock.set(500)  # before voting_start
    with pytest.raises(VotingWindowError):
        fe.dl.submit_ballot(fe.config.election_id, late, sig)

    assert fe.dl.count_ballots(fe.config.election_id) == 0


def test_out_of_band_out_of_window_ballot_is_excluded_at_tally(full_env):
    """Auditability half: a row that reaches storage *bypassing* the write gate
    (direct SQL, a second writer, a restored backup) is still excluded at tally time,
    because admission re-derives the window from the adapter's recorded receive time.
    Before this fix the row carried no receive time, so the check was skipped and the
    late ballot was silently counted."""
    fe = full_env
    _register_and_dkg(fe)
    fe.clock.set(1_500)
    good = fe.voter_ballot([3, 0, 0], b"\x01" * 32)
    submit_ballot(fe.dl, fe.config.election_id, good, clock=fe.clock, gateway_signer=fe.gateway)

    # Inject the way a bypass would: straight into storage, stamped after voting_end.
    late = fe.voter_ballot([0, 3, 0], b"\x02" * 32)
    stored = fe.dl._elections[fe.config.election_id]
    stored.ballots.append(
        StoredBallot(sequence_number=len(stored.ballots), envelope=late, submitted_at=2_400)
    )
    assert fe.dl.count_ballots(fe.config.election_id) == 2

    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)

    assert list(result.totals) == [3, 0, 0]  # the late ballot did not count
    agg_artifact = fe.dl.get_aggregate(fe.config.election_id)
    assert agg_artifact.admitted == (0,)
    assert [x.reason for x in agg_artifact.exclusions] == [ExclusionReason.OUT_OF_WINDOW]
    # And an auditor reading only public data reproduces the same exclusion.
    assert auditor.audit(fe.dl, fe.config.election_id).ok


# --------------------------------------------------------------------------- #
#  Keyper preconditions — never trust the trigger
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
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([1, 1, 1], b"\x01" * 32), clock=fe.clock, gateway_signer=fe.gateway)
    fe.clock.set(2_500)
    agg.trigger_aggregate(fe.keypers, fe.config.election_id)
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
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([1, 1, 1], b"\x01" * 32), clock=fe.clock, gateway_signer=fe.gateway)
    fe.clock.set(2_500)
    agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)

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
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32), clock=fe.clock, gateway_signer=fe.gateway)
    fe.clock.set(2_500)
    agg.trigger_aggregate(fe.keypers, fe.config.election_id)

    # Tamper: claim no ballots were admitted (simulating a malicious data layer that
    # rewrites the quorum-canonical aggregate under every keyper's submission).
    stored = fe.dl._elections[fe.config.election_id]
    tampered = replace(fe.dl.get_aggregate(fe.config.election_id), admitted=())
    stored.aggregate_by_keyper = {i: tampered for i in stored.aggregate_by_keyper}
    report = auditor.audit(fe.dl, fe.config.election_id)
    assert not report.aggregate_ok
    assert any("admitted set differs" in d for d in report.discrepancies)
