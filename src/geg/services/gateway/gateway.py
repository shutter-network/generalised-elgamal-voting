"""Ballot admission (gateway) — library.

The single-ballot admission filter used by the public API's ballot ingest
(``POST /elections/<eid>/ballots``). Runs the standard admission verification as a
**filter (on by default)** and writes accepted ballots to the data layer. The
filter is for UX (a voter learns immediately that a ballot is malformed) and
spam/storage protection; its accept/reject decision has **no bearing on tally
correctness** — verification is authoritative at tally time, and a compromised
ingress (or a direct-submission path) can inject unverified rows without affecting
the tally.

Duplicate handling is NOT done here (it is evaluated at tally time over the full
ordered list); this only checks single-ballot validity and the voting window.

This module has no HTTP surface of its own: the ingest endpoint lives on the
``api`` service (``geg.services.api``), which imports :func:`submit_ballot`.
"""

from __future__ import annotations

from geg.core.admission import StoredBallot, validate_ballot
from geg.crypto.points import g2_from_compressed
from geg.envelopes.types import AttestationScheme, BallotEnvelope
from geg.ports.data_layer import ElectionDataLayer
from geg.core.state import ElectionState, StateFacts, derive_state

# Page size for scanning stored ballots when computing a pseudonym's max nonce.
_NONCE_SCAN_PAGE = 200


class GatewayRejection(ValueError):
    """Raised when the (on-by-default) admission filter rejects a ballot."""


def _max_stored_nonce(dl: ElectionDataLayer, election_id: bytes, pseudonym: bytes) -> int:
    """Highest attestation nonce already stored for ``pseudonym`` (0 if none).

    Scans the stored ballots via the paginated ``list_ballots`` (no by-pseudonym index in
    the port). O(n) — acceptable for the reference implementation; a production data layer
    would expose an indexed lookup. Used only for the best-effort ingestion replay filter,
    NOT for tally correctness (that is the authoritative nonce ordering in ``admit``)."""
    total = dl.count_ballots(election_id)
    best = 0
    for off in range(0, total, _NONCE_SCAN_PAGE):
        for b in dl.list_ballots(election_id, off, _NONCE_SCAN_PAGE):
            if b.pseudonym == pseudonym and b.attestation.nonce > best:
                best = b.attestation.nonce
    return best


def submit_ballot(
    dl: ElectionDataLayer,
    election_id: bytes,
    ballot: BallotEnvelope,
    *,
    clock,
    filter_on: bool = True,
) -> int:
    """Accept a ballot iff the election is ``Voting``; filter it first if enabled.

    Returns the assigned sequence number. Raises :class:`GatewayRejection` if the
    window is closed or (when ``filter_on``) the ballot fails verification.
    """
    rec = dl.get_election(election_id)
    cfg = rec.config
    now = clock()

    facts = StateFacts(
        cancelled=rec.cancelled,
        key_finalized=rec.finalized_key is not None,
        result_published=dl.get_result(election_id) is not None,
    )
    if derive_state(cfg, facts, now) is not ElectionState.VOTING:
        raise GatewayRejection("voting is not open")

    if filter_on:
        if rec.finalized_key is None:  # cannot verify proofs without the key
            raise GatewayRejection("no finalized key")
        mpk = g2_from_compressed(rec.finalized_key.pk_election)
        # submitted_at=now so the window check is exercised by the same predicate.
        reason = validate_ballot(StoredBallot(-1, ballot, submitted_at=now), cfg, mpk)
        if reason is not None:
            raise GatewayRejection(reason.value)

        # Replay filter (funds/DoS defense, NOT the integrity boundary — see
        # REPLAY_PROTECTION_PLAN.md): reject a ballot whose signed re-vote nonce is not
        # strictly greater than the highest already stored for this pseudonym, so a replayed
        # old ballot never becomes a (sponsored, gas-paying) on-chain submitVote. Only for
        # ATTESTATION_V1 (LEGACY is nonceless — leave its behaviour unchanged). The tally's
        # nonce ordering remains authoritative regardless of what got stored.
        att = ballot.attestation
        if att.scheme is AttestationScheme.V1:
            if att.nonce <= _max_stored_nonce(dl, election_id, ballot.pseudonym):
                raise GatewayRejection("STALE_OR_REPLAYED")

    return dl.submit_ballot(election_id, ballot)
