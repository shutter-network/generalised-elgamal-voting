"""Tally library — recover + publish the result.

Aggregation is committee-owned: each keyper re-derives the deterministic aggregate
from the ordered ballots and submits it, and the data layer makes it canonical at
the ``t+1`` byte-identical quorum (mirroring the DKG-result quorum). This module
provides the *downstream* step — :func:`finalize`: once the canonical aggregate and
``t+1`` verified decryption shares exist, recover the totals (Lagrange + BSGS) and
**publish the result** (the one artifact signed by the ``result_publisher_key``).
The coordinator (:class:`geg.services.coordinator.AutoDKG`) drives the tally over
HTTP — trigger ``/aggregate`` → gate on the quorum aggregate → trigger ``/publish_decr_share`` →
call :func:`finalize` — and is itself the result publisher.

:func:`run_tally`, :func:`trigger_aggregate`, :func:`trigger_keypers` are the
**in-process test/simulation harness**: they take live ``KeyperService`` objects in
the *same process* and call their ``*_and_submit`` methods directly (write straight to
the shared data layer, no HTTP/relay/token bootstrap), so the protocol-level e2e tests
can drive a full election without standing up N keyper servers. They mirror the HTTP
path — both funnel through the same ``KeyperService.produce_*`` core; only the write
transport differs (the same split as the DKG ``run_dkg_once`` vs ``run_dkg_http``).
"""

from __future__ import annotations

from geg.core.aggregation import recover_result
from geg.core.authz import Signer
from geg.ports.data_layer import ElectionDataLayer
from geg.core.state import ElectionState, StateFacts, derive_state


class TallyError(RuntimeError):
    pass


def _state(dl: ElectionDataLayer, election_id: bytes, now: int):
    rec = dl.get_election(election_id)
    facts = StateFacts(
        cancelled=rec.cancelled,
        key_finalized=rec.finalized_key is not None,
        result_published=dl.get_result(election_id) is not None,
    )
    return rec, derive_state(rec.config, facts, now)


def trigger_aggregate(keypers, election_id: bytes) -> None:
    """**Test/simulation harness only** (the coordinator uses ``coord.trigger_aggregate_http``).
    Trigger each in-process keyper to aggregate. Failures are swallowed — the
    canonical-aggregate quorum on the data layer is the real success gate, and the
    next tick retries (keypers self-guard on ``votingEnd``)."""
    for k in keypers:
        try:
            k.aggregate_and_submit(election_id)
        except Exception:  # noqa: BLE001
            pass


def trigger_keypers(keypers, election_id: bytes) -> None:
    """**Test/simulation harness only** (the coordinator uses ``coord.trigger_decrypt_http``).
    Trigger each in-process keyper's decryption. Failures are
    swallowed — the share count on the data layer is the real success gate, and the
    next tick retries (keypers self-guard on their preconditions)."""
    for k in keypers:
        try:
            k.decrypt_and_submit(election_id)
        except Exception:  # noqa: BLE001
            pass


def finalize(dl: ElectionDataLayer, election_id: bytes, result_publisher: Signer, *, clock):
    """Collect ``t+1`` verified shares, recover totals, publish the result.

    Returns the published ``ResultArtifact``, or ``None`` if there are not yet
    enough valid shares (caller retries; ``Tallying`` is unbounded, so it simply
    stays open until enough shares arrive).
    """
    rec, state = _state(dl, election_id, clock())
    if state is ElectionState.COMPLETE:
        return dl.get_result(election_id)
    if state not in (ElectionState.TALLYING,):
        raise TallyError(f"cannot finalize: state is {state.value}")
    agg = dl.get_aggregate(election_id)
    if agg is None or rec.finalized_key is None:
        raise TallyError("cannot finalize: aggregate or key missing")

    shares = dl.list_decryption_shares(election_id)
    result = recover_result(
        rec.config, agg, shares, rec.finalized_key.committee_pks, rec.config.threshold.t
    )
    if result is None:
        return None  # not enough valid shares yet
    dl.publish_result(election_id, result, result_publisher.sign("result", election_id))
    return result


def run_tally(dl: ElectionDataLayer, election_id: bytes, result_publisher: Signer, keypers, *, clock):
    """**Test/simulation harness only** — the synchronous single-process equivalent of
    the coordinator's tally loop (no production caller; see the module docstring).
    Full pipeline: trigger in-process keypers to aggregate (quorum → canonical) →
    trigger decrypt → finalize. Returns the result.

    Keypers submit synchronously, so the ``t+1`` aggregate quorum is met before we
    proceed; the keypers compute the aggregate, this harness only drives them."""
    trigger_aggregate(keypers, election_id)
    if dl.get_aggregate(election_id) is None:
        raise TallyError("cannot proceed: no canonical (quorum) aggregate")
    trigger_keypers(keypers, election_id)
    return finalize(dl, election_id, result_publisher, clock=clock)
