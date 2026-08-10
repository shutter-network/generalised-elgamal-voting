"""Coordinator service.

The **single keyper-facing orchestrator**. Two roles in one daemon:

1. **Lifecycle watcher/driver** (``AutoDKG``) — discovers elections **from the data
   layer** (any adapter) and drives each through its whole keyper-driven lifecycle:
   ``Registered`` → run the DKG (bootstrap tokens, sequence the ceremony over HTTP,
   nearest-``voting_start``-first; ``DKGFailed`` if ``voting_start`` passes with no
   key); ``Tallying`` → trigger keypers to aggregate (canonical at the t+1 quorum),
   then to decrypt, then recover + **publish the result** (it holds the
   ``result_publisher_key``).

2. **Keyper-write relay** (``build_coordinator_app``) — the single service keypers
   submit their signed DKG results, aggregates, and decryption shares to
   (``POST /dkg-result`` / ``/aggregate`` / ``/decryption-share``). The coordinator
   forwards each to the data layer via its own ``dl``. On the **blockchain** backend
   that ``dl`` is bound to the coordinator's own account (``COORDINATOR_SIGNING_KEY``):
   it pays gas for the ``...Signed`` meta-tx (the contract ``ecrecover``s the keyper as
   author) *and* sends ``publishResult`` (it holds ``RESULT_PUBLISHER_ROLE``). Keypers
   never hold a data-layer write handle or a chain key — they only talk to the
   coordinator for writes (reads go to the uniform data-layer service URL).

The relay is thin: it does not verify the keyper signature itself (the data layer /
contract does, via recovery against the registered committee) — it only relays.
Endpoints are gated by a fail-closed bearer token (``COORDINATOR_API_TOKEN``).
"""

from __future__ import annotations

import logging
import time

from geg.ports.data_layer import ElectionDataLayer
from . import dkg_coordinator as coord
from geg.services import tally_aggregator as tally  # finalize (recover + publish result)
from geg.core.state import ElectionState, StateFacts, derive_state


class AutoDKG:
    """The sole keyper-facing orchestrator. Per poll it drives every election through
    its whole keyper-driven lifecycle: ``Registered`` → run the DKG; ``Tallying`` →
    trigger the keypers to aggregate (canonical at the t+1 quorum), then to decrypt,
    then recover + publish the result. It bootstraps each committee's tokens once and
    persists them privately. The coordinator is also the **result publisher**:
    ``self.coordinator`` signs the ``"result"`` write on db and, on chain, its account
    holds ``RESULT_PUBLISHER_ROLE`` (``config.result_publisher_key == coordinator address``)."""

    def __init__(self, data_layer: ElectionDataLayer, coordinator, *, clock,
                 poll_interval_s: float = 2.0, backoff_base_s: float = 10.0,
                 backoff_cap_s: float = 300.0, max_tally_attempts: int = 5,
                 url_overrides: dict[str, str] | None = None,
                 token_store=None, relay_token: str | None = None,
                 logger: logging.Logger | None = None):
        self.dl = data_layer
        self.coordinator = coordinator  # authz.Signer: pinned identity AND result publisher
        self.clock = clock
        self.poll_interval_s = poll_interval_s
        self.backoff_base_s = backoff_base_s
        self.backoff_cap_s = backoff_cap_s
        self.max_tally_attempts = max_tally_attempts
        # Address-keyed URL override for backends that don't store keyper URLs
        # — see geg.services.dkg_coordinator.keyper_urls_from. Normally empty.
        self.url_overrides = url_overrides or {}
        # Coordinator-private persistence for the minted keyper credentials, keyed by
        # keyper (stable per-keyper tokens): reloaded on restart so keypers are not
        # re-bootstrapped, and never churned when committees overlap.
        self.token_store = token_store
        # Write-relay bearer pushed to keypers via /auth/bootstrap (so they need no
        # pre-shared relay token). Equals the token this coordinator's relay gates on.
        self.relay_token = relay_token
        self.log = logger or logging.getLogger("geg.coordinator")
        self._done: set[str] = set()      # result published / Complete → terminal
        self._failed: set[str] = set()    # DKGFailed / DKG complaint → terminal
        # NB: a stalled tally is NOT tracked in memory — the persisted `tally_stalled` flag is
        # authoritative (the coordinator reads it each poll and skips), so a restart never
        # resurrects a stall. Only the admin's clearTallyStalled (retry) resumes it.
        self._attempts: dict[str, dict] = {}
        self._tally_attempts: dict[str, dict] = {}  # eid_hex → {"agg": n, "dec": n} (per-run counter)
        self._tokens_by_committee: dict[tuple, dict] = {}
        self._tally_phase: dict[str, str] = {}  # eid_hex → last-logged tally phase (dedupes per-poll spam)

    # -- helpers ------------------------------------------------------------ #

    def _keyper_urls(self, config) -> dict[int, str]:
        return coord.keyper_urls_from(config, self.url_overrides)

    def _member_addrs(self, config) -> dict[int, bytes]:
        """Keyper index (1-based) → config member (signing) address — the trust anchor
        each keyper's encryption pubkey is verified against before sealing. Sourced from
        the data-layer config, so it is identical on the db and chain backends."""
        return {i: bytes(k.signing_key) for i, k in enumerate(config.keypers, start=1)}

    def _bootstrap(self, urls: dict[int, str], member_addrs: dict[int, bytes]) -> dict[int, str]:
        """Full ``/auth/bootstrap`` of the committee: reuse-or-mint each keyper's stable
        credential and install it + this committee's peer map on every member. Used to
        drive the DKG (the ceremony needs the correct peer map). Returns
        ``{index → api_token}`` and caches it."""
        api_tokens, _peer = coord.bootstrap_keypers(
            self.coordinator, urls, member_addrs=member_addrs,
            relay_token=self.relay_token, token_store=self.token_store)
        self._tokens_by_committee[tuple(sorted(urls.items()))] = api_tokens
        self.log.info("op=bootstrap status=ok committee=%d", len(urls))
        return api_tokens

    def _committee_tokens(self, urls: dict[int, str], member_addrs: dict[int, bytes]) -> dict[int, str]:
        """Return ``{index → api_token}`` for this committee — the cheap path used by the
        tally (no peer map needed). Served from the in-memory cache, else reassembled
        from the per-keyper store; only if a member has no stable credential yet (or
        there is no store) does it fall back to a full :meth:`_bootstrap`."""
        key = tuple(sorted(urls.items()))
        if key in self._tokens_by_committee:
            return self._tokens_by_committee[key]
        if self.token_store is not None:
            assembled: dict[int, str] = {}
            for i, url in urls.items():
                cred = self.token_store.get(url)
                if cred is None:
                    break
                assembled[i] = cred["api_token"]
            else:  # every member had a persisted credential — reuse without re-installing
                self._tokens_by_committee[key] = assembled
                return assembled
        return self._bootstrap(urls, member_addrs)

    def _rebootstrap_one(self, urls: dict[int, str], member_addrs: dict[int, bytes], i: int) -> str | None:
        """401 safety net: re-install keyper ``i``'s stable credential (+ this committee's
        peer map) and return its api_token. Per-keyper credentials mean this never
        disturbs the other members, so it can't ping-pong between concurrent elections."""
        try:
            api_tokens, _peer = coord.bootstrap_keypers(
                self.coordinator, urls, member_addrs=member_addrs, relay_token=self.relay_token,
                token_store=self.token_store, install={i})
            self._tokens_by_committee[tuple(sorted(urls.items()))] = api_tokens
            self.log.info("op=rebootstrap status=ok keyper=%d committee=%d", i, len(urls))
            return api_tokens[i]
        except Exception as err:  # noqa: BLE001
            self.log.error("op=rebootstrap status=error keyper=%d err=%s", i, err)
            return None

    # -- scan --------------------------------------------------------------- #

    def _process(self, election_id: bytes, rec, now: int) -> str:
        eid_hex = election_id.hex()
        result_published = self.dl.get_result(election_id) is not None
        facts = StateFacts(
            cancelled=rec.cancelled, key_finalized=rec.finalized_key is not None,
            result_published=result_published, tally_stalled=rec.tally_stalled,
        )
        state = derive_state(rec.config, facts, now)

        if state is ElectionState.COMPLETE:
            self._done.add(eid_hex)
            return "complete"
        if state is ElectionState.DKG_FAILED:
            self._failed.add(eid_hex)
            self.log.warning("op=dkg status=failed election=%s (voting_start passed without a key)", eid_hex)
            return "dkg_failed"
        if state is ElectionState.REGISTERED:
            return self._drive_dkg(election_id, rec, now)
        if state is ElectionState.TALLYING:
            return self._drive_tally(election_id, rec)
        if state is ElectionState.TALLY_STALLED:
            # The persisted flag is authoritative: the coordinator does NOT drive a stalled
            # tally (a restart never resurrects it). Only the admin's clearTallyStalled
            # (retry) flips it back to Tallying, and the next poll resumes with a fresh budget.
            return "tally_stalled"
        return "not_ready"  # KeyReady / Voting / Cancelled

    def _tally_transition(self, eid_hex: str, phase: str) -> None:
        """Log a tally phase change once (``_drive_tally`` runs every poll, so logging
        unconditionally would spam ``aggregating`` at the poll interval — dedupe on the
        last-logged phase per election)."""
        if self._tally_phase.get(eid_hex) != phase:
            self._tally_phase[eid_hex] = phase
            self.log.info("op=tally status=%s election=%s", phase, eid_hex)

    def _mark_tally_stalled(self, election_id: bytes) -> None:
        """Persist the stalled flag (result-publisher auth). The coordinator only ever
        *marks* — clearing is the admin's retry. Best-effort: a write failure must never
        break the tally loop (the mark is retried next poll)."""
        try:
            self.dl.set_tally_stalled(election_id, True, self.coordinator.sign("tally_stall", election_id))
        except Exception as err:  # noqa: BLE001
            self.log.warning("op=tally status=mark_stalled_error election=%s err=%s", election_id.hex(), err)

    def _drive_dkg(self, election_id: bytes, rec, now: int) -> str:
        eid_hex = election_id.hex()
        # Back-off gate so we don't hammer between polls.
        att = self._attempts.setdefault(eid_hex, {"attempts": 0, "next_at": 0.0})
        if now < att["next_at"]:
            return "backing_off"

        urls = self._keyper_urls(rec.config)
        if any(not u for u in urls.values()):
            self.log.error("op=dkg status=error election=%s reason=missing_keyper_urls", eid_hex)
            return "no_urls"

        member_addrs = self._member_addrs(rec.config)
        try:
            # DKG needs the correct peer map installed → full bootstrap before the ceremony.
            self.log.info("op=dkg status=starting election=%s committee=%d attempt=%d",
                          eid_hex, len(urls), att["attempts"] + 1)
            api_tokens = self._bootstrap(urls, member_addrs)
            if coord.run_dkg_http(election_id, urls, api_tokens, self.dl,
                                  rebootstrap=lambda i: self._rebootstrap_one(urls, member_addrs, i)):
                self.log.info("op=dkg status=finalized election=%s", eid_hex)
                return "finalized"
        except coord.DKGComplaint as err:
            # A committee member complained about a dealer's shares. Terminal: a divergent
            # transcript can never finalize, so halt before publish and don't retry to the
            # deadline. Signed accusations are logged by run_dkg_http for manual resolution.
            self._failed.add(eid_hex)
            self.log.error("op=dkg status=halted_complaint election=%s err=%s", eid_hex, err)
            return "dkg_complaint"
        except Exception as err:  # noqa: BLE001 — retried next poll
            self.log.error("op=dkg status=error election=%s err=%s", eid_hex, err)

        att["attempts"] += 1
        att["next_at"] = now + min(self.backoff_cap_s, self.backoff_base_s * (2 ** (att["attempts"] - 1)))
        return "registered_retry"

    def _drive_tally(self, election_id: bytes, rec) -> str:
        """Tallying, in strict order: (past ``votingEnd``, guaranteed by the TALLYING
        state) trigger aggregate → gate on the canonical (quorum) aggregate → only then
        trigger decrypt → recover + publish. Idempotent per poll; keypers self-guard on
        ``votingEnd`` / canonical-aggregate and may override their aggregate until the
        quorum finalizes, so transient divergence self-heals.

        Each phase is bounded by ``max_tally_attempts`` polls: a tally that never reaches
        a quorum aggregate, or never collects ``t+1`` decryption shares, is **abandoned**
        (terminal + alert) rather than retriggered forever. A coordinator restart clears
        the counters and grants a fresh budget."""
        eid_hex = election_id.hex()
        urls = self._keyper_urls(rec.config)
        if any(not u for u in urls.values()):
            self.log.error("op=tally status=error election=%s reason=missing_keyper_urls", eid_hex)
            return "no_urls"
        member_addrs = self._member_addrs(rec.config)
        try:
            api_tokens = self._committee_tokens(urls, member_addrs)
        except Exception as err:  # noqa: BLE001
            self.log.error("op=tally status=bootstrap_error election=%s err=%s", eid_hex, err)
            return "error"
        rebootstrap = lambda i: self._rebootstrap_one(urls, member_addrs, i)  # noqa: E731 — 401 safety net
        att = self._tally_attempts.setdefault(eid_hex, {"agg": 0, "dec": 0})
        # Fresh budget on resume: `_drive_tally` is only reached when the flag is clear
        # (state Tallying). An exhausted counter here therefore means the admin cleared a
        # prior stall (the retry) — reset and try again from zero.
        if att["agg"] >= self.max_tally_attempts or att["dec"] >= self.max_tally_attempts:
            self.log.info("op=tally status=retrying election=%s (admin cleared the stall — fresh budget)", eid_hex)
            att = self._tally_attempts[eid_hex] = {"agg": 0, "dec": 0}

        def _abandon(phase: str, n: int) -> str:
            # Mark the persisted flag (result-publisher auth). The coordinator skips the
            # election hereafter (state → TallyStalled); only the admin's retry clears it.
            self._mark_tally_stalled(election_id)
            self.log.error("op=tally status=abandoned phase=%s election=%s attempts=%d — "
                           "stalled; admin 'retry' (clearTallyStalled) required to resume",
                           phase, eid_hex, n)
            return "tally_abandoned"

        # 1. Aggregate phase — trigger + gate on the canonical (t+1) quorum aggregate.
        #    Only ever reached in TALLYING (votingEnd already passed), so aggregation is
        #    never triggered before voting closes.
        if self.dl.get_aggregate(election_id) is None:
            self._tally_transition(eid_hex, "aggregating")
            coord.trigger_aggregate_http(election_id, urls, api_tokens, rebootstrap=rebootstrap)
            if self.dl.get_aggregate(election_id) is None:  # still no quorum this poll
                att["agg"] += 1
                return _abandon("aggregate", att["agg"]) if att["agg"] >= self.max_tally_attempts \
                    else "collecting_aggregate"

        # 2. Decrypt phase — a canonical aggregate exists; trigger decrypt, then finalize.
        self._tally_transition(eid_hex, "decrypting")
        coord.trigger_decrypt_http(election_id, urls, api_tokens, rebootstrap=rebootstrap)
        result = tally.finalize(self.dl, election_id, self.coordinator, clock=self.clock)
        if result is not None:
            self._done.add(eid_hex)
            self.log.info("op=tally status=finalized election=%s", eid_hex)
            return "tallied"
        att["dec"] += 1
        return _abandon("decrypt", att["dec"]) if att["dec"] >= self.max_tally_attempts \
            else "collecting_shares"

    def scan_once(self) -> dict[str, str]:
        """One pass over the data layer; returns {election_id_hex: outcome}.

        Elections that still need attention are processed **nearest-first**
        (ascending ``voting_start``): since driving a DKG blocks until it
        finalizes or fails, the election closest to opening gets the committee
        first when several need a key at once.
        """
        now = self.clock()
        outcomes: dict[str, str] = {}
        pending = []
        for election_id in self.dl.list_elections():
            eid_hex = election_id.hex()
            if eid_hex in self._done:
                outcomes[eid_hex] = "complete"
                continue
            if eid_hex in self._failed:
                outcomes[eid_hex] = "already_failed"
                continue
            try:
                pending.append((election_id, self.dl.get_election(election_id)))
            except Exception as err:  # noqa: BLE001
                self.log.error("op=scan status=error election=%s err=%s", eid_hex, err)
                outcomes[eid_hex] = "error"

        pending.sort(key=lambda pair: pair[1].config.voting_start)  # nearest election first
        for election_id, rec in pending:
            eid_hex = election_id.hex()
            try:
                outcomes[eid_hex] = self._process(election_id, rec, now)
            except Exception as err:  # noqa: BLE001
                self.log.error("op=scan status=error election=%s err=%s", eid_hex, err)
                outcomes[eid_hex] = "error"
        return outcomes

    def run_forever(self, *, sleep=time.sleep, stop=None) -> None:
        """Poll loop. ``stop`` (optional) is a predicate; when it returns True, exit."""
        while stop is None or not stop():
            try:
                self.scan_once()
            except Exception as err:  # noqa: BLE001
                self.log.error("op=scan status=error err=%s", err)
            sleep(self.poll_interval_s)


# --------------------------------------------------------------------------- #
#  Keyper-write relay (HTTP): keypers submit signed artifacts; we write them
# --------------------------------------------------------------------------- #

def build_coordinator_app(dl: ElectionDataLayer, *, api_token: str | None):
    """Flask app for keyper write submissions, relayed to ``dl``.

    ``POST /dkg-result``     — {electionId, pkElection, committeePKs, keyperSig}
    ``POST /decryption-share`` — {electionId, share, keyperSig}
    Both gated by ``Authorization: Bearer <COORDINATOR_API_TOKEN>`` (fail-closed).
    """
    from flask import Flask, jsonify, request

    from geg.envelopes import codecs
    from geg.ports.data_layer import ImmutabilityError, VotingWindowError, WriteAuthorizationError

    log = logging.getLogger("geg.coordinator")
    app = Flask(__name__)

    def _reject(status: int, kind: str, e, *, level: int = logging.WARNING):
        # Log every data-layer rejection of a relayed keyper write at the service
        # boundary — the data-layer adapter itself is a library and stays quiet, so this
        # is where a refused aggregate/share/DKG-result write becomes visible.
        log.log(level, "op=relay status=rejected path=%s http=%d error=%s msg=%s",
                request.path, status, kind, e)
        return jsonify(error=kind, message=str(e)), status

    @app.errorhandler(KeyError)
    def _not_found(e):
        return _reject(404, "KeyError", e)

    @app.errorhandler(WriteAuthorizationError)
    def _forbidden(e):
        return _reject(403, "WriteAuthorizationError", e)  # non-keyper / bad signature

    @app.errorhandler(ImmutabilityError)
    def _conflict(e):
        # Often a benign quorum race (the t+1 aggregate/DKG result finalized just before
        # this byte-identical write landed) — info, not warning.
        return _reject(409, "ImmutabilityError", e, level=logging.INFO)

    @app.errorhandler(VotingWindowError)
    def _unprocessable(e):
        # Out-of-order tally write (before voting_end, or a share before a canonical
        # aggregate) — mirrors the data-layer service's 422 mapping.
        return _reject(422, "VotingWindowError", e)

    @app.errorhandler(ValueError)
    def _bad_request(e):
        return _reject(400, "ValueError", e)

    @app.before_request
    def _auth():
        if request.path == "/health":
            return None
        if not api_token:  # fail-closed: no token configured → no relay
            return jsonify(error="Unauthorized", message="coordinator relay not configured"), 503
        header = request.headers.get("Authorization", "")
        presented = header[7:] if header.startswith("Bearer ") else ""
        if presented != api_token:
            return jsonify(error="Unauthorized", message="bad or missing coordinator token"), 401
        return None

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    @app.post("/dkg-result")
    def dkg_result():
        body = request.get_json(force=True)
        dl.submit_dkg_result(
            codecs.dec_bytes(body["electionId"], name="electionId"),
            codecs.dec_bytes(body["pkElection"], name="pkElection"),
            [codecs.dec_bytes(p, name="committeePKs[]") for p in body["committeePKs"]],
            codecs.dec_bytes(body["keyperSig"], name="keyperSig"),
        )
        return "", 204

    @app.post("/decryption-share")
    def decryption_share():
        body = request.get_json(force=True)
        dl.submit_decryption_share(
            codecs.dec_bytes(body["electionId"], name="electionId"),
            codecs.dec_decryption_share(body["share"]),
            codecs.dec_bytes(body["keyperSig"], name="keyperSig"),
        )
        return "", 204

    @app.post("/aggregate")
    def aggregate():
        body = request.get_json(force=True)
        dl.submit_aggregate(
            codecs.dec_bytes(body["electionId"], name="electionId"),
            codecs.dec_aggregate(body["aggregate"]),
            codecs.dec_bytes(body["keyperSig"], name="keyperSig"),
        )
        return "", 204

    return app


class CoordinatorClient:
    """Keyper-side write client — POSTs signed artifacts to the coordinator relay.

    Duck-types the two ``ElectionDataLayer`` write methods keypers use, so a keyper
    server can take *either* a data-layer handle (write directly) or this (write via
    the coordinator) as its ``submitter``. Reads still go through the keyper's own
    data-layer handle.
    """

    def __init__(self, url: str, token: str, *, timeout: float = 30.0):
        import requests

        self._requests = requests
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _post(self, path: str, body: dict) -> None:
        r = self._requests.post(
            self.url + path, json=body,
            headers={"Authorization": f"Bearer {self.token}"}, timeout=self.timeout,
        )
        r.raise_for_status()

    def submit_dkg_result(self, election_id, pk_election, committee_pks, keyper_sig) -> None:
        from geg.envelopes import codecs

        self._post("/dkg-result", {
            "electionId": codecs.enc_bytes(election_id),
            "pkElection": codecs.enc_bytes(pk_election),
            "committeePKs": [codecs.enc_bytes(c) for c in committee_pks],
            "keyperSig": codecs.enc_bytes(keyper_sig),
        })

    def submit_decryption_share(self, election_id, share, keyper_sig) -> None:
        from geg.envelopes import codecs

        self._post("/decryption-share", {
            "electionId": codecs.enc_bytes(election_id),
            "share": codecs.enc_decryption_share(share),
            "keyperSig": codecs.enc_bytes(keyper_sig),
        })

    def submit_aggregate(self, election_id, aggregate, keyper_sig) -> None:
        from geg.envelopes import codecs

        self._post("/aggregate", {
            "electionId": codecs.enc_bytes(election_id),
            "aggregate": codecs.enc_aggregate(aggregate),
            "keyperSig": codecs.enc_bytes(keyper_sig),
        })


def main() -> None:
    """Run the coordinator: the single keyper-facing orchestrator + keyper-write relay.

    One daemon drives every election end to end — DKG (Registered), then the tally
    (Tallying: trigger keypers to aggregate → quorum → decrypt → recover + publish the
    result).

    Env: ``COORDINATOR_SIGNING_KEY`` (hex secp256k1 — the coordinator identity keypers
    pin as ``COORDINATOR_IDENTITY``, **and** the ``result_publisher_key``: it signs the
    result write on db and, on chain, is the funded account that relays keyper meta-tx
    *and* sends ``publishResult`` holding ``RESULT_PUBLISHER_ROLE``). ``GEG_DATA_LAYER`` +
    ``GEG_DATA_LAYER_URL`` (http backends); ``COORDINATOR_API_TOKEN`` (relay bearer,
    fail-closed if unset); ``COORDINATOR_STATE_DIR`` (private volume the minted keyper
    tokens persist to, reloaded on restart); ``COORDINATOR_HOST``/``COORDINATOR_PORT``
    (default 8400), ``COORDINATOR_POLL_S``. Keyper URLs come from the election config on
    every backend (the KeyperSet contract on chain), not from env.
    """
    import os
    import threading
    import time as _time

    from geg.core.authz import Signer
    from geg.services.common.backend import data_layer_for_service
    from geg.services.common.token_store import TokenStore

    logging.basicConfig(level=logging.INFO)
    coordinator_key = os.environ["COORDINATOR_SIGNING_KEY"]
    coordinator = Signer.from_sk(int(coordinator_key, 16))
    # On chain the coordinator's own account is the funded relayer + result publisher
    # (it holds RESULT_PUBLISHER_ROLE); on http backends the key is ignored (writes go
    # via HttpDataLayerClient) and the coordinator signs the result request instead.
    dl = data_layer_for_service(coordinator_key)
    # Coordinator-private token persistence (reloaded on restart; not shared).
    store_dir = os.environ.get("COORDINATOR_STATE_DIR")
    relay_token = os.environ.get("COORDINATOR_API_TOKEN")  # pushed to keypers via bootstrap
    watcher = AutoDKG(
        dl, coordinator, clock=lambda: int(_time.time()),
        poll_interval_s=float(os.environ.get("COORDINATOR_POLL_S", "2.0")),
        token_store=TokenStore(store_dir) if store_dir else None,
        relay_token=relay_token,
    )
    logging.getLogger("geg.coordinator").info("op=start coordinator_identity=%s", coordinator.identity.hex())
    threading.Thread(target=watcher.run_forever, daemon=True).start()

    app = build_coordinator_app(dl, api_token=os.environ.get("COORDINATOR_API_TOKEN"))
    app.run(host=os.environ.get("COORDINATOR_HOST", "0.0.0.0"),
            port=int(os.environ.get("COORDINATOR_PORT", "8400")), threaded=True)


if __name__ == "__main__":
    main()
