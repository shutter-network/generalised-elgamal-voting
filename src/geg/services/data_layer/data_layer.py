"""Uniform data-layer HTTP service.

One Flask microservice that exposes the ``ElectionDataLayer`` port over HTTP (the
JSON envelopes) wrapping **any** backend adapter — in-memory, Postgres, or
blockchain. A deployment picks the backend with ``GEG_DATA_LAYER`` and every
component (keypers, gateway, coordinator, admin) speaks the same HTTP
to it via :class:`geg.adapters.db.client.HttpDataLayerClient`, unchanged. The
routes call only port methods, so the service is genuinely backend-agnostic.

All reads are public and unauthenticated; writes carry the actor's signature
which the backend verifies. Contract violations surface as typed HTTP statuses
the client maps back to the port's exception types:

    404 KeyError · 403 WriteAuthorizationError · 409 ImmutabilityError ·
    422 VotingWindowError · 400 ValueError

Backend semantics (``GEG_DATA_LAYER``):

* ``memory`` / ``database`` — the store verifies each write's signature (request
  sig for admin/gateway and the coordinator's result write; content sig +
  ``ecrecover`` for keyper writes) and writes. Every route is a usable write path.
* ``blockchain`` — the service is the **public read surface** on chain, wrapping a
  read-only :class:`~geg.adapters.chain.client.BlockchainDataLayer` (no write account).
  Keyper writes are relayed by the **coordinator** (whose ``COORDINATOR_SIGNING_KEY``
  account sends the ``...Signed`` meta-tx and pays gas; the contract ``ecrecover``s the
  keyper), and admin/gateway submit their own txs directly (``msg.sender`` authz). So
  on-chain identity is never impersonated here.
"""

from __future__ import annotations

from flask import Flask, jsonify, request

from geg.envelopes import codecs
from geg.ports.data_layer import (
    ElectionDataLayer,
    ElectionFilter,
    FinalizedKey,
    ImmutabilityError,
    VotingWindowError,
    WriteAuthorizationError,
)


def _finalized_key_json(fk: FinalizedKey | None):
    if fk is None:
        return None
    return {
        "pkElection": codecs.enc_bytes(fk.pk_election),
        "committeePKs": [codecs.enc_bytes(p) for p in fk.committee_pks],
    }


def build_app(dl: ElectionDataLayer) -> Flask:
    """Build the Flask app mapping the port onto HTTP routes over any adapter."""
    app = Flask(__name__)

    @app.errorhandler(KeyError)
    def _not_found(e):
        return jsonify(error="KeyError", message=str(e)), 404

    @app.errorhandler(WriteAuthorizationError)
    def _forbidden(e):
        return jsonify(error="WriteAuthorizationError", message=str(e)), 403

    @app.errorhandler(ImmutabilityError)
    def _conflict(e):
        return jsonify(error="ImmutabilityError", message=str(e)), 409

    @app.errorhandler(VotingWindowError)
    def _wrong_window(e):
        return jsonify(error="VotingWindowError", message=str(e)), 422

    @app.errorhandler(ValueError)
    def _bad_request(e):
        return jsonify(error="ValueError", message=str(e)), 400

    def _eid() -> bytes:
        return bytes.fromhex(request.view_args["eid"])

    # -- election lifecycle ------------------------------------------------- #

    @app.post("/elections")
    def register():
        body = request.get_json(force=True)
        config = codecs.dec_config(body["config"])
        sig = codecs.dec_bytes(body["adminSig"], name="adminSig")
        eid = dl.register_election(config, sig)
        return jsonify(electionId=codecs.enc_bytes(eid)), 200

    @app.post("/elections/<eid>/cancel")
    def cancel(eid):
        body = request.get_json(force=True)
        dl.cancel_election(_eid(), codecs.dec_bytes(body["adminSig"], name="adminSig"))
        return "", 204

    @app.get("/elections/<eid>")
    def get_election(eid):
        rec = dl.get_election(_eid())
        return jsonify(
            config=codecs.enc_config(rec.config),
            cancelled=rec.cancelled,
            tallyStalled=rec.tally_stalled,
            finalizedKey=_finalized_key_json(rec.finalized_key),
        )

    @app.get("/elections")
    def list_elections():
        admin_key = request.args.get("adminKey")
        filt = ElectionFilter(admin_key=codecs.dec_bytes(admin_key, name="adminKey")) if admin_key else None
        return jsonify(electionIds=[codecs.enc_bytes(e) for e in dl.list_elections(filt)])

    # -- DKG ---------------------------------------------------------------- #

    @app.post("/elections/<eid>/dkg")
    def submit_dkg(eid):
        body = request.get_json(force=True)
        dl.submit_dkg_result(
            _eid(),
            codecs.dec_bytes(body["pkElection"], name="pkElection"),
            [codecs.dec_bytes(p, name="committeePKs[]") for p in body["committeePKs"]],
            codecs.dec_bytes(body["keyperSig"], name="keyperSig"),
        )
        return "", 204

    @app.get("/elections/<eid>/dkg")
    def get_dkg(eid):
        return jsonify(submissions=[codecs.enc_dkg_result(s) for s in dl.get_dkg_submissions(_eid())])

    @app.get("/elections/<eid>/dkg/finalized")
    def get_finalized(eid):
        return jsonify(finalizedKey=_finalized_key_json(dl.get_finalized_key(_eid())))

    # -- ballots ------------------------------------------------------------ #

    @app.post("/elections/<eid>/ballots")
    def submit_ballot(eid):
        body = request.get_json(force=True)
        seq = dl.submit_ballot(_eid(), codecs.dec_ballot(body["ballot"]))
        return jsonify(sequenceNumber=seq), 200

    @app.get("/elections/<eid>/ballots")
    def list_ballots(eid):
        start = int(request.args.get("start", 0))
        count = int(request.args.get("count", 0))
        return jsonify(ballots=[codecs.enc_ballot(b) for b in dl.list_ballots(_eid(), start, count)])

    @app.get("/elections/<eid>/ballots/count")
    def count_ballots(eid):
        return jsonify(count=dl.count_ballots(_eid()))

    # -- tally artifacts ---------------------------------------------------- #

    @app.post("/elections/<eid>/aggregate")
    def submit_aggregate(eid):
        body = request.get_json(force=True)
        dl.submit_aggregate(
            _eid(), codecs.dec_aggregate(body["aggregate"]),
            codecs.dec_bytes(body["keyperSig"], name="keyperSig"),
        )
        return "", 204

    @app.get("/elections/<eid>/aggregate")
    def get_aggregate(eid):
        agg = dl.get_aggregate(_eid())
        return jsonify(aggregate=codecs.enc_aggregate(agg) if agg else None)

    @app.post("/elections/<eid>/shares")
    def submit_share(eid):
        body = request.get_json(force=True)
        dl.submit_decryption_share(
            _eid(), codecs.dec_decryption_share(body["share"]),
            codecs.dec_bytes(body["keyperSig"], name="keyperSig"),
        )
        return "", 204

    @app.get("/elections/<eid>/shares")
    def list_shares(eid):
        return jsonify(shares=[codecs.enc_decryption_share(s) for s in dl.list_decryption_shares(_eid())])

    @app.post("/elections/<eid>/result")
    def publish_result(eid):
        body = request.get_json(force=True)
        dl.publish_result(
            _eid(), codecs.dec_result(body["result"]),
            codecs.dec_bytes(body["resultPublisherSig"], name="resultPublisherSig"),
        )
        return "", 204

    @app.get("/elections/<eid>/result")
    def get_result(eid):
        res = dl.get_result(_eid())
        return jsonify(result=codecs.enc_result(res) if res else None)

    @app.post("/elections/<eid>/tally-stalled")
    def set_tally_stalled(eid):
        body = request.get_json(force=True)
        dl.set_tally_stalled(
            _eid(), bool(body["stalled"]),
            codecs.dec_bytes(body["resultPublisherSig"], name="resultPublisherSig"),
        )
        return "", 204

    # -- capability --------------------------------------------------------- #

    @app.get("/capability")
    def capability():
        return jsonify(verifiabilityTier=dl.verifiability_tier())

    return app


def _build_backend(clock):
    """Construct the backend adapter selected by ``GEG_DATA_LAYER`` (default database)."""
    import os

    backend = os.environ.get("GEG_DATA_LAYER", "database").strip().lower()

    if backend in ("memory", "in-memory", "inmemory"):
        from geg.adapters.memory import InMemoryDataLayer

        return InMemoryDataLayer(clock=clock)

    if backend in ("database", "db", "postgres", "postgresql"):
        from geg.adapters.db import DEFAULT_DSN
        from geg.adapters.db.store import PostgresStore

        store = PostgresStore(os.environ.get("GEG_DATA_LAYER_DSN", DEFAULT_DSN), clock=clock)
        store.init_schema()
        return store

    if backend in ("blockchain", "chain", "eth"):
        from web3 import Web3

        from geg.adapters.chain.client import BlockchainDataLayer

        rpc = os.environ["GEG_CHAIN_RPC"]
        registry = os.environ["GEG_REGISTRY_ADDRESS"]
        # The data-layer service is the READ-ONLY public read surface on chain (no
        # write account): admin/gateway submit their own txs, and keyper writes are
        # relayed by the coordinator.
        w3 = Web3(Web3.HTTPProvider(rpc))
        return BlockchainDataLayer(w3, registry, account=None)

    raise SystemExit(f"unknown GEG_DATA_LAYER={backend!r} (want memory|database|blockchain)")


def main() -> None:
    """Run the uniform data-layer microservice for the ``GEG_DATA_LAYER`` backend.

    Env: ``GEG_DATA_LAYER`` (memory|database|blockchain); ``DATA_LAYER_HOST`` /
    ``DATA_LAYER_PORT``. Backend-specific: ``GEG_DATA_LAYER_DSN`` (database);
    ``GEG_CHAIN_RPC`` / ``GEG_REGISTRY_ADDRESS`` (blockchain, read-only).
    Uses wall-clock (NTP-disciplined in deployment) as the adapter's authoritative
    time for immutability + voting-window enforcement.
    """
    import logging
    import os
    import time

    logging.basicConfig(level=logging.INFO)
    backend = os.environ.get("GEG_DATA_LAYER", "database").strip().lower()
    port = int(os.environ.get("DATA_LAYER_PORT", "8000"))
    logging.getLogger("geg.data_layer").info("op=start service=data-layer backend=%s port=%d", backend, port)
    dl = _build_backend(lambda: int(time.time()))
    app = build_app(dl)
    app.run(host=os.environ.get("DATA_LAYER_HOST", "0.0.0.0"), port=port)


if __name__ == "__main__":
    main()
