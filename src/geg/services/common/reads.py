"""Shared client-side read helpers over the ``ElectionDataLayer`` port.

Paging belongs here rather than in an adapter: the port's ``list_ballots(start, count)``
is deliberately a *page* API so no single request can be made unbounded, and
every consumer that needs the whole ballot list must therefore loop.
"""

from __future__ import annotations

from geg.envelopes.types import StoredBallot
from geg.ports.data_layer import ElectionDataLayer

# Rows per request when walking the full ballot list. Bounded so one call can never
# stream an entire election (the DoS risk) and, on the chain backend, so a read
# is many small ``getBallots`` calls rather than one huge eth_call that a real RPC may
# refuse or truncate. Must not exceed the server-side cap in ``port_read_blueprint``.
BALLOT_PAGE = 1000


class IncompleteBallotRead(RuntimeError):
    """Raised when paging could not recover the complete, contiguous ballot list.

    Loud on purpose. A silently short read is the worst outcome available here: each
    keyper would aggregate a *different* subset, so the ``t+1`` byte-identical quorum
    would never form and the tally would stall with nothing pointing at the cause.
    """


def read_all_ballots(dl: ElectionDataLayer, election_id: bytes) -> list[StoredBallot]:
    """Every stored ballot, in the data layer's stable total order.

    Pages through :meth:`~geg.ports.data_layer.ElectionDataLayer.list_ballots` and then
    **verifies completeness**: the port guarantees a stable total order with monotonic
    sequence numbers, and all three adapters assign them contiguously from 0 (memory:
    ``len``; DB: ``MAX(seq)+1``; chain: ``ballotRecords.length-1``). So the result must be
    exactly ``0..total-1`` — anything else means a truncated page, a lying data layer, or
    a gap, and is raised rather than returned.

    Ballots are append-only, so a concurrent write can only extend past ``total``; the
    prefix being paged is stable. (At tally time the election is past ``voting_end`` and
    the write gate refuses new ballots anyway, so the set is frozen.)
    """
    total = dl.count_ballots(election_id)
    out: list[StoredBallot] = []
    start = 0
    while start < total:
        page = dl.list_ballots(election_id, start, min(BALLOT_PAGE, total - start))
        if not page:
            raise IncompleteBallotRead(
                f"election {election_id.hex()}: empty page at offset {start} but "
                f"{total} ballots are reported — the read was truncated"
            )
        out.extend(page)
        start += len(page)

    got = [sb.sequence_number for sb in out]
    if got != list(range(total)):
        raise IncompleteBallotRead(
            f"election {election_id.hex()}: expected contiguous sequence numbers "
            f"0..{total - 1}, got {len(got)} rows starting {got[:5]}"
        )
    return out
