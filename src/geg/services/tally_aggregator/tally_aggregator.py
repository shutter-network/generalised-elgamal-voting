"""Tally aggregator daemon (DESIGN.md §2, §8.1, §8.3).

Admin-operated. In this (trust-minimized) phase the aggregator is **trigger-only**
for the aggregate: it no longer computes the aggregate itself. The committee owns
aggregation — each keyper re-derives the deterministic aggregate from the ordered
ballots and submits it, and the data layer makes it canonical at the ``t+1``
byte-identical quorum (mirroring the DKG-result quorum). The aggregator only
*drives* the pipeline: trigger keypers to aggregate → wait for the canonical
(quorum) aggregate → trigger keypers to decrypt → collect and verify ``t+1`` shares
→ recover → **publish the result** (the one artifact still signed by the
``aggregator_key``). Idempotent and safe to re-run: it re-reads data-layer state
before each step.

Two layers live in this module — do not confuse them:

* **Deployment path (production):** :class:`TallyAggregatorDaemon`. It reaches the
  keypers **over HTTP** — ``coord.trigger_aggregate_http`` / ``trigger_decrypt_http``
  POST to each keyper's ``/aggregate`` / ``/decrypt`` endpoint, which relays the
  keyper's signed artifact through the coordinator to the data layer. This is what
  runs in a real multi-operator deployment.
* **In-process test/simulation harness (never deployed):** the module functions
  :func:`run_tally`, :func:`trigger_aggregate`, :func:`trigger_keypers` take live
  ``KeyperService`` objects in the *same process* and call their ``*_and_submit``
  methods directly (write straight to the shared data layer, no HTTP/relay/token
  bootstrap). Used only by the protocol-level e2e tests so they can drive a full
  election without standing up N keyper servers. They have **no production caller**;
  both layers funnel through the same ``KeyperService.produce_*`` core, so the only
  difference is the write transport. (Mirrors the DKG ``run_dkg_once`` vs
  ``run_dkg_http`` split.)
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
    """**Test/simulation harness only** (not a deployment path — see module docstring;
    the daemon uses ``coord.trigger_aggregate_http``). Trigger each in-process keyper
    to aggregate. Failures are swallowed — the canonical-aggregate quorum on the data
    layer is the real success gate, and the next tick retries (keypers self-guard on
    ``votingEnd``)."""
    for k in keypers:
        try:
            k.aggregate_and_submit(election_id)
        except Exception:  # noqa: BLE001
            pass


def trigger_keypers(keypers, election_id: bytes, *, hardened: bool = False) -> None:
    """**Test/simulation harness only** (the daemon uses ``coord.trigger_decrypt_http``).
    Trigger each in-process keyper's decryption (sx-monorepo model). Failures are
    swallowed — the share count on the data layer is the real success gate, and the
    next tick retries (keypers self-guard via §8.2 preconditions)."""
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
    """**Test/simulation harness only** — the synchronous single-process equivalent of
    :class:`TallyAggregatorDaemon` (no production caller; see the module docstring).
    Full pipeline: trigger in-process keypers to aggregate (quorum → canonical) →
    trigger decrypt → finalize. Returns the result.

    Keypers submit synchronously, so the ``t+1`` aggregate quorum is met before we
    proceed. The aggregator never computes the aggregate itself."""
    trigger_aggregate(keypers, election_id)
    if dl.get_aggregate(election_id) is None:
        raise TallyError("cannot proceed: no canonical (quorum) aggregate")
    trigger_keypers(keypers, election_id, hardened=hardened)
    return finalize(dl, election_id, aggregator, clock=clock)


# --------------------------------------------------------------------------- #
#  Watcher daemon — discover Tallying elections and drive the pipeline
# --------------------------------------------------------------------------- #

class TallyAggregatorDaemon:
    """Standing daemon (DESIGN.md §2, §4.2): poll the data layer for elections in
    ``Tallying`` and drive trigger-aggregate → gate on the quorum aggregate → trigger
    decrypt → finalize, until a result exists or the election goes ``Void`` at
    ``tally_deadline``.

    Trigger-only for the aggregate: the committee owns aggregation (keypers submit; the
    data layer makes it canonical at the t+1 quorum), so this daemon never computes the
    aggregate. It holds the ``aggregator`` identity only to sign the **result** write.
    To trigger keypers it does **not** bootstrap them — the
    **coordinator** is the sole bootstrapper and hands off the keyper api-tokens via
    a shared :class:`~geg.services.common.token_store.TokenStore`, which this daemon
    only **reads**. That keeps the keyper's single token slot owned by one writer
    (no churn) and means the keypers need not trust the aggregator at all. Elections
    are processed **nearest-deadline first**.
    """

    def __init__(self, data_layer: ElectionDataLayer, aggregator: Signer, *, clock,
                 hardened: bool = False, poll_interval_s: float = 2.0,
                 endpoints: dict[str, str] | None = None, token_store=None, logger=None):
        import logging
        self.dl = data_layer
        self.aggregator = aggregator
        self.clock = clock
        self.hardened = hardened
        self.poll_interval_s = poll_interval_s
        # Address-keyed endpoint override for backends that don't store endpoints
        # (e.g. blockchain) — see geg.services.dkg_coordinator.keyper_urls_from.
        self.endpoints = endpoints or {}
        # Read-only handle on the shared store the coordinator wrote keyper tokens to.
        self.token_store = token_store
        self.log = logger or logging.getLogger("geg.tally_aggregator")
        self._done: set[str] = set()
        self._void: set[str] = set()

    def _keyper_urls(self, config) -> dict[int, str]:
        from geg.services.coordinator import dkg_coordinator as coord

        return coord.keyper_urls_from(config, self.endpoints)

    def _decrypt_tokens(self, urls: dict[int, str]) -> dict[int, str]:
        """Read the coordinator-minted keyper api-tokens from the shared store."""
        if self.token_store is None:
            raise RuntimeError("no token store configured; cannot obtain keyper tokens")
        tokens = self.token_store.read(urls)
        if tokens is None:
            raise RuntimeError("keyper tokens not in shared store yet (coordinator has not bootstrapped this committee)")
        return tokens

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

        # 1. Trigger keypers to aggregate over HTTP; the committee owns aggregation
        #    now. The canonical aggregate exists only once t+1 keypers submit the
        #    same one (data-layer quorum) — the aggregator never computes it.
        urls = self._keyper_urls(rec.config)
        api_tokens = None
        if all(urls.values()):
            try:
                api_tokens = self._decrypt_tokens(urls)
                coord.trigger_aggregate_http(election_id, urls, api_tokens)
            except Exception as err:  # noqa: BLE001
                self.log.error("op=trigger-aggregate status=error election=%s err=%s", eid_hex, err)

        # 2. Gate on the canonical (quorum) aggregate. If not yet reached, retry next tick.
        if self.dl.get_aggregate(election_id) is None:
            return "collecting_aggregate"

        # 3. Trigger keypers to decrypt over HTTP (best-effort; keypers self-guard via §8.2).
        if api_tokens is not None:
            try:
                coord.trigger_decrypt_http(election_id, urls, api_tokens, hardened=self.hardened)
            except Exception as err:  # noqa: BLE001
                self.log.error("op=trigger status=error election=%s err=%s", eid_hex, err)

        # 4. Finalize if t+1 verified shares are in.
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

    Env: ``AGGREGATOR_SIGNING_KEY`` (hex secp256k1 — the aggregatorKey identity and
    the tx sender for publishResult on chain; the aggregate is now keyper-submitted,
    not aggregator-published), ``GEG_TOKEN_STORE``
    (the shared volume the coordinator wrote keyper tokens to; read-only here),
    ``GEG_DATA_LAYER``, ``GEG_DATA_LAYER_URL`` (http backends), ``TALLY_POLL_S``,
    ``TALLY_HARDENED`` (0/1). It does **not** bootstrap keypers — the coordinator is
    the sole bootstrapper. Keyper URLs come from the election config (stored in the
    data layer on every backend), not from env.
    """
    import logging
    import os
    import time as _time

    from geg.core.authz import Signer
    from geg.services.common.backend import data_layer_for_service
    from geg.services.common.token_store import TokenStore

    logging.basicConfig(level=logging.INFO)
    aggregator_key = os.environ["AGGREGATOR_SIGNING_KEY"]
    aggregator = Signer.from_sk(int(aggregator_key, 16))
    dl = data_layer_for_service(aggregator_key)
    store_dir = os.environ.get("GEG_TOKEN_STORE")
    daemon = TallyAggregatorDaemon(
        dl, aggregator, clock=lambda: int(_time.time()),
        hardened=os.environ.get("TALLY_HARDENED", "0") == "1",
        poll_interval_s=float(os.environ.get("TALLY_POLL_S", "2.0")),
        token_store=TokenStore(store_dir) if store_dir else None,
    )
    daemon.run_forever()


if __name__ == "__main__":
    main()
