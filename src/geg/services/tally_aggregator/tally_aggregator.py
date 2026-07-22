"""Tally aggregator daemon (DESIGN.md §2, §8.1, §8.3).

Admin-operated and trusted for privacy (§3). Watches for elections entering
``Tallying`` and runs the pipeline: fetch the ordered ballot list → admit
(verify + duplicate policy) → weighted homomorphic aggregate with its admitted
set → publish → trigger keypers → collect and verify ``t+1`` shares → recover →
publish the result. Idempotent and safe to re-run: it re-reads data-layer state
before each write.
"""

from __future__ import annotations

from geg.core.admission import StoredBallot, admit
from geg.core.aggregation import build_aggregate_artifact, recover_result
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


def publish_aggregate(dl: ElectionDataLayer, election_id: bytes, aggregator: Signer, *, clock) -> None:
    """Admit ballots and publish the weighted aggregate (idempotent)."""
    rec, state = _state(dl, election_id, clock())
    if state not in (ElectionState.TALLYING, ElectionState.COMPLETE):
        raise TallyError(f"cannot aggregate: state is {state.value}")
    if dl.get_aggregate(election_id) is not None:
        return  # already published
    if rec.finalized_key is None:
        raise TallyError("cannot aggregate: no finalized key")

    n = dl.count_ballots(election_id)
    stored = [StoredBallot(i, env) for i, env in enumerate(dl.list_ballots(election_id, 0, n))]
    result = admit(stored, rec.config, rec.finalized_key.pk_election)
    artifact = build_aggregate_artifact(rec.config, result)
    dl.publish_aggregate(election_id, artifact, aggregator.sign("aggregate", election_id))


def trigger_keypers(keypers, election_id: bytes, *, hardened: bool = False) -> None:
    """Trigger each keyper's decryption (sx-monorepo model). Failures are swallowed —
    the share count on the data layer is the real success gate, and the next tick
    retries (keypers self-guard via §8.2 preconditions)."""
    for k in keypers:
        try:
            k.decrypt_and_submit(election_id, hardened=hardened)
        except Exception:  # noqa: BLE001
            pass


def finalize(dl: ElectionDataLayer, election_id: bytes, aggregator: Signer, *, clock):
    """Collect ``t+1`` verified shares, recover totals, publish the result.

    Returns the published ``ResultArtifact``, or ``None`` if there are not yet
    enough valid shares (caller retries; ``Void`` if never satisfied by deadline).
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
    dl.publish_result(election_id, result, aggregator.sign("result", election_id))
    return result


def run_tally(dl: ElectionDataLayer, election_id: bytes, aggregator: Signer, keypers, *,
              clock, hardened: bool = False):
    """Full pipeline: aggregate → trigger keypers → finalize. Returns the result."""
    publish_aggregate(dl, election_id, aggregator, clock=clock)
    trigger_keypers(keypers, election_id, hardened=hardened)
    return finalize(dl, election_id, aggregator, clock=clock)


# --------------------------------------------------------------------------- #
#  Watcher daemon — discover Tallying elections and drive the pipeline
# --------------------------------------------------------------------------- #

class TallyAggregatorDaemon:
    """Standing daemon (DESIGN.md §2, §4.2): poll the data layer for elections in
    ``Tallying`` and drive aggregate → trigger keypers (HTTP) → finalize, until a
    result exists or the election goes ``Void`` at ``tally_deadline``.

    Holds only the ``aggregator`` identity: it signs the aggregate/result writes
    **and** bootstraps + triggers the keypers over HTTP with that same key. The
    keypers pin the aggregator's address as a trusted bootstrapper (alongside the
    coordinator's), so the aggregator never needs the coordinator's key. By tally
    time DKG is finished, so re-bootstrapping the committee is harmless. Elections
    are processed **nearest-deadline first**.
    """

    def __init__(self, data_layer: ElectionDataLayer, aggregator: Signer, *, clock,
                 hardened: bool = False, poll_interval_s: float = 2.0,
                 endpoints: dict[str, str] | None = None, logger=None):
        import logging
        self.dl = data_layer
        self.aggregator = aggregator
        self.clock = clock
        self.hardened = hardened
        self.poll_interval_s = poll_interval_s
        # Address-keyed endpoint override for backends that don't store endpoints
        # (e.g. blockchain) — see geg.services.dkg_coordinator.keyper_urls_from.
        self.endpoints = endpoints or {}
        self.log = logger or logging.getLogger("geg.tally_aggregator")
        self._done: set[str] = set()
        self._void: set[str] = set()
        self._tokens_by_committee: dict[tuple, dict] = {}

    def _keyper_urls(self, config) -> dict[int, str]:
        from geg.services.coordinator import dkg_coordinator as coord

        return coord.keyper_urls_from(config, self.endpoints)

    def _ensure_bootstrapped(self, urls: dict[int, str]) -> dict[int, str]:
        from geg.services.coordinator import dkg_coordinator as coord
        key = tuple(sorted(urls.items()))
        if key not in self._tokens_by_committee:
            api_tokens, _peer = coord.bootstrap_keypers(self.aggregator, urls)
            self._tokens_by_committee[key] = api_tokens
        return self._tokens_by_committee[key]

    def _process(self, election_id: bytes, rec, now: int) -> str:
        from geg.services.coordinator import dkg_coordinator as coord
        eid_hex = election_id.hex()
        if self.dl.get_result(election_id) is not None:
            self._done.add(eid_hex)
            return "already_tallied"

        facts = StateFacts(cancelled=rec.cancelled, key_finalized=rec.finalized_key is not None,
                           result_published=False)
        state = derive_state(rec.config, facts, now)
        if state is ElectionState.VOID:
            self._void.add(eid_hex)
            self.log.warning("op=tally status=void election=%s (no result by tally_deadline)", eid_hex)
            return "void"
        if state is not ElectionState.TALLYING:
            return "not_ready"

        # 1. Publish the aggregate (idempotent).
        publish_aggregate(self.dl, election_id, self.aggregator, clock=self.clock)

        # 2. Trigger keypers over HTTP (best-effort; keypers self-guard via §8.2).
        urls = self._keyper_urls(rec.config)
        if all(urls.values()):
            try:
                api_tokens = self._ensure_bootstrapped(urls)
                coord.trigger_decrypt_http(election_id, urls, api_tokens, hardened=self.hardened)
            except Exception as err:  # noqa: BLE001
                self.log.error("op=trigger status=error election=%s err=%s", eid_hex, err)

        # 3. Finalize if t+1 verified shares are in.
        result = finalize(self.dl, election_id, self.aggregator, clock=self.clock)
        if result is not None:
            self._done.add(eid_hex)
            self.log.info("op=tally status=finalized election=%s", eid_hex)
            return "tallied"
        return "collecting_shares"

    def scan_once(self) -> dict[str, str]:
        now = self.clock()
        outcomes: dict[str, str] = {}
        pending = []
        for election_id in self.dl.list_elections():
            eid_hex = election_id.hex()
            if eid_hex in self._done:
                outcomes[eid_hex] = "already_tallied"
                continue
            if eid_hex in self._void:
                outcomes[eid_hex] = "void"
                continue
            try:
                pending.append((election_id, self.dl.get_election(election_id)))
            except Exception as err:  # noqa: BLE001
                self.log.error("op=scan status=error election=%s err=%s", eid_hex, err)
                outcomes[eid_hex] = "error"
        pending.sort(key=lambda pair: pair[1].config.tally_deadline)  # nearest deadline first
        for election_id, rec in pending:
            eid_hex = election_id.hex()
            try:
                outcomes[eid_hex] = self._process(election_id, rec, now)
            except Exception as err:  # noqa: BLE001
                self.log.error("op=scan status=error election=%s err=%s", eid_hex, err)
                outcomes[eid_hex] = "error"
        return outcomes

    def run_forever(self, *, sleep=None, stop=None) -> None:
        import time
        sleep = sleep or time.sleep
        while stop is None or not stop():
            try:
                self.scan_once()
            except Exception as err:  # noqa: BLE001
                self.log.error("op=scan status=error err=%s", err)
            sleep(self.poll_interval_s)


def main() -> None:
    """Run the tally aggregator daemon against the database data-layer microservice.

    Env: ``AGGREGATOR_SIGNING_KEY`` (hex secp256k1 — the aggregatorKey identity, the
    tx sender for publishAggregate/publishResult on chain, **and** the key it uses to
    bootstrap/trigger keypers — the keypers pin its address as a trusted
    bootstrapper), ``GEG_DATA_LAYER``, ``GEG_DATA_LAYER_URL`` (http backends),
    ``TALLY_POLL_S``, ``TALLY_HARDENED`` (0/1). Keyper URLs come from the election
    config (stored in the data layer on every backend), not from env.
    """
    import logging
    import os
    import time as _time

    from geg.core.authz import Signer
    from geg.services.common.backend import data_layer_for_service

    logging.basicConfig(level=logging.INFO)
    aggregator_key = os.environ["AGGREGATOR_SIGNING_KEY"]
    aggregator = Signer.from_sk(int(aggregator_key, 16))
    dl = data_layer_for_service(aggregator_key)
    daemon = TallyAggregatorDaemon(
        dl, aggregator, clock=lambda: int(_time.time()),
        hardened=os.environ.get("TALLY_HARDENED", "0") == "1",
        poll_interval_s=float(os.environ.get("TALLY_POLL_S", "2.0")),
    )
    daemon.run_forever()


if __name__ == "__main__":
    main()
