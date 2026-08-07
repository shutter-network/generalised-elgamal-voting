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
from geg.envelopes.types import BallotEnvelope
from geg.ports.data_layer import ElectionDataLayer
from geg.core.state import ElectionState, StateFacts, derive_state


class GatewayRejection(ValueError):
    """Raised when the (on-by-default) admission filter rejects a ballot."""


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

    return dl.submit_ballot(election_id, ballot)
