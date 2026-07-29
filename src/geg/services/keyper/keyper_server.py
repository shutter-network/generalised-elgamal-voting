"""Deployable keyper HTTP service (sx-monorepo model, geg ports).

One process per committee member. Wraps the keyper crypto (`KeyperDKGState`,
partial decryption) behind an authenticated HTTP API the DKG coordinator drives,
with confidential round-2 shares travelling **directly keyper→keyper**. Secrets
persist encrypted at rest (:mod:`geg.services.keyper_persistence`) so the process
survives the gap between DKG and decryption.

Auth (fail-closed until bootstrapped): coordinator→keyper endpoints require the
``api_token``; keyper→keyper (`/dkg/receive_*`) require the callee's ``peer_token``;
``/status``, ``/health``, ``/auth/bootstrap`` are open. Tokens are installed via a
one-time X25519-sealed + coordinator-signed :func:`/auth/bootstrap` and persisted.

The server never trusts a decryption trigger — `/decrypt` re-checks the §8.2
preconditions against the data layer (via :class:`KeyperService`).
"""

from __future__ import annotations

import json
import logging
import threading

import requests
from flask import Flask, abort, jsonify, request

from geg.core import write_auth
from geg.crypto.dkg import KeyperDKGState, derive_joint_mpk, derive_mpk_share
from geg.crypto.points import g2_from_compressed, g2_to_compressed
from geg.ports.data_layer import ImmutabilityError
from . import keyper_bootstrap as boot
from . import keyper_persistence as persist
from .keyper import KeyperService

_OPEN = {"/status", "/health", "/auth/bootstrap"}
_PEER = {"/dkg/receive_commitments", "/dkg/receive_share"}
_SECRET_RETENTION_BUFFER_S = 86_400  # keep the share ~1 day past tally_deadline


def _is_benign_write_conflict(err: Exception) -> bool:
    """True if a keyper write lost a benign race: the artifact it is submitting is
    already canonical/recorded, so its (byte-identical) contribution wasn't needed.

    Happens when the ``t+1`` quorum finalizes the aggregate (or enough decryption
    shares land) just before this keyper's submission — expected with a committee
    larger than the threshold. A **direct** write raises :class:`ImmutabilityError`;
    a write **via the coordinator relay** surfaces the same as an HTTP ``409``. Either
    way it is not a fault — distinct from a real 4xx/5xx, which still propagates."""
    if isinstance(err, ImmutabilityError):
        return True
    resp = getattr(err, "response", None)  # requests.HTTPError from the relay
    return resp is not None and resp.status_code == 409


def build_keyper_app(signer, data_layer, trusted_identities, *, clock, state_dir,
                     submitter=None, logger=None):
    """Build a keyper Flask app bound to one committee identity (`signer`).

    ``trusted_identities`` is the pinned set of bootstrapper addresses the keyper
    accepts on ``/auth/bootstrap`` — a single 20-byte address or an iterable (the
    coordinator, the sole keyper bootstrapper). ``state_dir`` is this keyper's private
    encrypted-state directory. Reads go to
    ``data_layer``; **writes** (DKG result, aggregate, decryption shares) go to ``submitter`` —
    which defaults to ``data_layer`` (direct write, in-process/simple deployments) or
    is a :class:`~geg.services.coordinator.CoordinatorClient` that POSTs the signed
    artifacts to the coordinator relay (the multi-operator path). Either way the
    keyper only ever *signs* — the data layer / contract verifies authorship.
    """
    import pathlib

    submitter = submitter or data_layer
    trusted_identities = boot.as_identity_set(trusted_identities)
    log = logger or logging.getLogger("geg.keyper")
    state_dir = pathlib.Path(state_dir)
    app = Flask(__name__)
    lock = threading.Lock()

    fernet = persist.derive_fernet(signer.private_key)
    x25519 = persist.load_or_create_x25519(fernet, state_dir, log)
    completed: dict[str, persist.DkgEntry] = {}
    persist.load_dkg_secrets(fernet, completed, state_dir, log)
    dkg_states: dict[str, KeyperDKGState] = {}
    inbox: dict[str, dict] = {}
    nonce_tracker = boot.NonceTracker()

    tokens = persist.load_bootstrap_tokens(fernet, state_dir, log) or {}
    installed = {
        "api_token": tokens.get("api_token"),
        "peer_token": tokens.get("peer_token"),
        "relay_token": tokens.get("relay_token"),  # keyper→coordinator relay bearer (pushed via bootstrap)
        "peers": tokens.get("peers", {}),
    }

    def _apply_relay_token() -> None:
        # The relay bearer is pushed over /auth/bootstrap (not pre-shared), so point
        # the write client (CoordinatorClient) at it. Reloaded from state on restart.
        if submitter is not data_layer and hasattr(submitter, "token") and installed["relay_token"]:
            submitter.token = installed["relay_token"]

    _apply_relay_token()
    persist.start_prune_loop(completed, fernet, state_dir, log, lock)

    # -- helpers ------------------------------------------------------------ #

    def _eid(body) -> bytes:
        return bytes.fromhex(body["electionId"])

    def _config(election_id: bytes):
        return data_layer.get_election(election_id).config

    def _my_index(config) -> int:
        for i, k in enumerate(config.keypers, start=1):
            if k.signing_key == signer.identity:
                return i
        abort(403, "this keyper is not in the election's keyper set")

    def _inbox(eid_hex: str) -> dict:
        return inbox.setdefault(eid_hex, {"commitments": {}, "shares": {}})

    def _peer(index: int) -> dict:
        return installed["peers"][str(index)]

    def _post_peer(index: int, path: str, body: dict) -> None:
        p = _peer(index)
        requests.post(p["url"].rstrip("/") + path, json=body,
                      headers={"Authorization": f"Bearer {p['token']}"}, timeout=10).raise_for_status()

    # -- auth --------------------------------------------------------------- #

    @app.before_request
    def _require_bearer():
        if request.path in _OPEN:
            return
        if installed["api_token"] is None:
            abort(503, "keyper not bootstrapped")
        tok = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        expected = installed["peer_token"] if request.path in _PEER else installed["api_token"]
        if not tok or tok != expected:
            abort(401, "bad bearer token")

    # -- status + bootstrap ------------------------------------------------- #

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    @app.get("/status")
    def status():
        return jsonify(
            identity=signer.identity.hex(),
            bootstrapped=installed["api_token"] is not None,
            encryptionPubkey=x25519.public_key().public_bytes_raw().hex(),
            elections=sorted(completed.keys()),
        )

    @app.post("/auth/bootstrap")
    def bootstrap():
        body = request.get_json(force=True)
        try:
            payload = json.loads(boot.x25519_unseal(bytes.fromhex(body["sealed"]), x25519).decode())
        except Exception:  # noqa: BLE001
            abort(400, "cannot unseal bootstrap payload")
        if not boot.verify_payload(trusted_identities, payload, bytes.fromhex(body["signature"])):
            abort(401, "untrusted bootstrapper signature")
        if not nonce_tracker.check_and_record(payload.get("nonce", ""), int(payload.get("timestamp", 0))):
            abort(401, "stale or replayed bootstrap")
        with lock:
            installed["api_token"] = str(payload["api_token"])
            installed["peer_token"] = str(payload["peer_token"])
            installed["peers"] = dict(payload["peers"])
            relay = payload.get("relay_token")
            if relay:  # pushed by the coordinator so keypers need no pre-shared relay token
                installed["relay_token"] = str(relay)
                _apply_relay_token()
            persist.save_bootstrap_tokens(fernet, installed["api_token"], installed["peer_token"],
                                          installed["peers"], state_dir, relay_token=installed["relay_token"])
        log.info("op=bootstrap status=installed peers=%d", len(installed["peers"]))
        return jsonify(ok=True)

    # -- DKG ---------------------------------------------------------------- #

    @app.post("/dkg/round1")
    def dkg_round1():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        idx = _my_index(config)
        n, t = config.threshold.n, config.threshold.t
        with lock:
            st = KeyperDKGState()
            st.round1(idx, n, t)
            dkg_states[eid_hex] = st
            _inbox(eid_hex)  # reset/init
            inbox[eid_hex] = {"commitments": {idx: st.commitments}, "shares": {idx: st.shares_for_others[idx]}}
        return jsonify(ok=True, index=idx)

    @app.post("/dkg/distribute_commitments")
    def dkg_distribute_commitments():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        idx = _my_index(config)
        commitments_hex = [g2_to_compressed(c).hex() for c in dkg_states[eid_hex].commitments]
        for peer_index in range(1, config.threshold.n + 1):
            if peer_index == idx:
                continue
            _post_peer(peer_index, "/dkg/receive_commitments",
                       {"electionId": eid_hex, "dealerIndex": idx, "commitments": commitments_hex})
        return jsonify(ok=True)

    @app.post("/dkg/receive_commitments")
    def dkg_receive_commitments():
        body = request.get_json(force=True)
        eid_hex = body["electionId"]
        dealer = int(body["dealerIndex"])
        incoming = [bytes.fromhex(h) for h in body["commitments"]]
        with lock:
            box = _inbox(eid_hex)["commitments"]
            if dealer in box:
                if [g2_to_compressed(c) for c in box[dealer]] != incoming:
                    abort(409, "different commitments already received from this dealer")
            else:
                box[dealer] = [g2_from_compressed(b) for b in incoming]
        return jsonify(ok=True)

    @app.post("/dkg/distribute_shares")
    def dkg_distribute_shares():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        idx = _my_index(config)
        st = dkg_states[eid_hex]
        for recipient in range(1, config.threshold.n + 1):
            if recipient == idx:
                continue
            _post_peer(recipient, "/dkg/receive_share",
                       {"electionId": eid_hex, "dealerIndex": idx, "recipientIndex": recipient,
                        "share": hex(st.shares_for_others[recipient])})
        return jsonify(ok=True)

    @app.post("/dkg/receive_share")
    def dkg_receive_share():
        body = request.get_json(force=True)
        eid_hex = body["electionId"]
        dealer = int(body["dealerIndex"])
        share = int(body["share"], 16)
        with lock:
            shares = _inbox(eid_hex)["shares"]
            if dealer in shares and shares[dealer] != share:
                abort(409, "different share already received from this dealer")
            shares[dealer] = share
        return jsonify(ok=True)

    @app.post("/dkg/round2")
    def dkg_round2():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        config = _config(eid)
        st = dkg_states[eid_hex]
        box = _inbox(eid_hex)
        try:
            st.round2(box["commitments"], box["shares"])
        except ValueError as err:
            return jsonify(verified=False, complaints=getattr(err, "bad_dealers", [])), 200
        with lock:
            completed[eid_hex] = persist.DkgEntry(
                combined_share=st.combined_share,
                expires_at=int(config.tally_deadline) + _SECRET_RETENTION_BUFFER_S,
            )
            persist.save_dkg_secrets(fernet, completed, state_dir)
        return jsonify(verified=True)

    @app.post("/dkg/publish")
    def dkg_publish():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        commitments = _inbox(eid_hex)["commitments"]
        pk = derive_joint_mpk(commitments)
        committee = [derive_mpk_share(i, commitments) for i in sorted(commitments)]
        pk_b = g2_to_compressed(pk)
        committee_b = [g2_to_compressed(c) for c in committee]
        sig = write_auth.sign_dkg_result(signer.private_key, eid, pk_b, committee_b)
        submitter.submit_dkg_result(eid, pk_b, committee_b, sig)  # direct or via coordinator relay
        return jsonify(ok=True)

    # -- aggregation (keyper-quorum; deterministic re-derivation from ballots) #

    @app.post("/aggregate")
    def aggregate():
        body = request.get_json(force=True)
        eid = _eid(body)
        config = _config(eid)
        # No persisted DKG secret needed — aggregation only reads the ordered
        # ballot list and re-runs admission (self-guarded on votingEnd inside).
        ks = KeyperService(_my_index(config), signer, data_layer, clock=clock)
        try:
            produced = ks.produce_aggregate(eid)
        except Exception as err:  # noqa: BLE001 — refusal / precondition failure
            return jsonify(ok=False, reason=str(err)), 409
        if produced is not None:  # None = already submitted (idempotent)
            artifact, sig = produced
            try:
                submitter.submit_aggregate(eid, artifact, sig)  # direct or via coordinator relay
            except Exception as err:  # noqa: BLE001
                if not _is_benign_write_conflict(err):
                    raise
                # The t+1 quorum finalized the (identical) aggregate before this
                # submission landed — canonical already; this keyper wasn't needed.
                return jsonify(ok=True, note="aggregate already finalized by quorum"), 200
        return jsonify(ok=True)

    # -- partial decryption (§8.2 preconditions enforced by KeyperService) -- #

    @app.post("/decrypt")
    def decrypt():
        body = request.get_json(force=True)
        eid = _eid(body); eid_hex = eid.hex()
        entry = completed.get(eid_hex)
        if entry is None:
            abort(409, "no persisted DKG share for this election")
        config = _config(eid)
        ks = KeyperService(_my_index(config), signer, data_layer, clock=clock)  # data_layer = reads
        ks.dkg.combined_share = entry.combined_share
        ks.dkg.public_key_share = entry.public_key_share
        try:
            produced = ks.produce_decryption_share(eid)
        except Exception as err:  # noqa: BLE001 — refusal / precondition failure
            return jsonify(ok=False, reason=str(err)), 409
        if produced is not None:  # None = already submitted (idempotent)
            share, sig = produced
            try:
                submitter.submit_decryption_share(eid, share, sig)  # direct or via coordinator relay
            except Exception as err:  # noqa: BLE001
                if not _is_benign_write_conflict(err):
                    raise
                # Enough shares already recorded before this one landed — benign.
                return jsonify(ok=True, note="decryption share already recorded"), 200
        return jsonify(ok=True)

    return app


def main() -> None:
    """Run one keyper process against the database data-layer microservice.

    Env: ``KEYPER_SIGNING_KEY`` (hex secp256k1 scalar — this keyper's Ethereum
    identity, whose 20-byte address is its committee identity), ``COORDINATOR_IDENTITY``
    (hex 20-byte address the keyper pins for bootstrap auth — the coordinator is the
    **sole** bootstrapper), ``GEG_DATA_LAYER_URL``
    (the uniform data-layer service — used for **reads** only), ``COORDINATOR_URL``
    (where the keyper POSTs its signed DKG result / decryption shares — the
    coordinator relays them; if unset, writes go directly to the data layer). The
    relay bearer token is **not** an env var: the coordinator pushes it over
    ``/auth/bootstrap`` and it persists in state. ``KEYPER_STATE_DIR``,
    ``KEYPER_HOST``/``KEYPER_PORT``.
    """
    import os
    import time

    from geg.adapters.db.client import HttpDataLayerClient
    from geg.core.authz import Signer
    from geg.services.coordinator import CoordinatorClient

    logging.basicConfig(level=logging.INFO)
    signer = Signer.from_sk(int(os.environ["KEYPER_SIGNING_KEY"], 16))
    # The coordinator is the sole keyper bootstrapper; pin only its identity.
    trusted_identities = {bytes.fromhex(os.environ["COORDINATOR_IDENTITY"].removeprefix("0x"))}
    data_layer = HttpDataLayerClient(os.environ["GEG_DATA_LAYER_URL"])
    state_dir = os.environ.get("KEYPER_STATE_DIR", "/keyper-state")

    # Writes go to the coordinator relay when configured; otherwise directly to the
    # data layer (reads always use the data-layer handle). The relay bearer token is
    # NOT pre-shared — the coordinator pushes it over /auth/bootstrap, and the keyper
    # applies it to this client (persisted, so it survives restart). Start empty.
    coordinator_url = os.environ.get("COORDINATOR_URL")
    submitter = CoordinatorClient(coordinator_url, "") if coordinator_url else None

    app = build_keyper_app(signer, data_layer, trusted_identities,
                           clock=lambda: int(time.time()), state_dir=state_dir, submitter=submitter)
    app.run(host=os.environ.get("KEYPER_HOST", "0.0.0.0"), port=int(os.environ.get("KEYPER_PORT", "8100")))


if __name__ == "__main__":
    main()
