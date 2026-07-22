"""Election admin service (DESIGN.md §2, §4.1).

The sole writer of election config: registers elections with full parameter
validation (including the DKG lead-time gate), cancels strictly before
``voting_start``, and triggers tallying. Config becomes immutable after
``voting_start`` (enforced by the data layer).

Exposed three ways over the same pure functions: a CLI (``register`` / ``cancel``),
and an admin-only HTTP service (``serve``) a frontend can drive. The committee for
an election — keyper identities **and their URLs** — is part of the register config,
so a new election can name a different or partly-replaced keyper set (k1,k2,k3 vs
k2,k3,k4); on the database backend those URLs are stored and read back by the
coordinator/aggregator (no env needed).

Auth is model **A** (DESIGN note): the service holds ``ADMIN_SIGNING_KEY`` and the
HTTP endpoints are gated by a fail-closed bearer token (``ADMIN_API_TOKEN``). Model
B (frontend signs, server relays — key never on the server) is a later-version TODO.
"""

from __future__ import annotations

from geg.core.authz import Signer
from geg.core.config import ElectionConfig
from geg.ports.data_layer import ElectionDataLayer


class RegistrationError(ValueError):
    pass


def register_election(
    dl: ElectionDataLayer,
    config: ElectionConfig,
    admin: Signer,
    *,
    clock,
    dkg_lead_time: int,
) -> bytes:
    """Register an election. Rejected unless ``voting_start - now >= dkg_lead_time``.

    ``ElectionConfig`` already validates its internal invariants (candidate count,
    budget, weight bounds, schedule ordering, keyper count) at construction; this
    adds the deployment lead-time gate (the ``MIN_DKG_LEAD_TIME`` pattern) so the
    DKG has room to complete and retry before voting opens.
    """
    if config.admin_key != admin.identity:
        raise RegistrationError("admin signer does not match config.admin_key")
    now = clock()
    if config.voting_start - now < dkg_lead_time:
        raise RegistrationError(
            f"insufficient DKG lead time: voting_start - now = {config.voting_start - now} "
            f"< dkg_lead_time = {dkg_lead_time}"
        )
    return dl.register_election(config, admin.sign_register(config))


def cancel_election(dl: ElectionDataLayer, election_id: bytes, admin: Signer) -> None:
    """Cancel before ``voting_start`` (the data layer rejects it once voting starts)."""
    dl.cancel_election(election_id, admin.sign("cancel", election_id))


# --------------------------------------------------------------------------- #
#  Admin HTTP service (auth model A: bearer token, admin-only, fail-closed)
# --------------------------------------------------------------------------- #

def build_admin_app(dl: ElectionDataLayer, admin: Signer, *, clock, dkg_lead_time: int, api_token: str | None):
    """Flask app exposing register/cancel to the admin (a frontend, later).

    Every route requires ``Authorization: Bearer <ADMIN_API_TOKEN>``; if no token is
    configured the service is fail-closed (503 on writes). ``/health`` is open.
    """
    from flask import Flask, jsonify, request

    from geg.envelopes import codecs
    from geg.ports.data_layer import ImmutabilityError, WriteAuthorizationError

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

    @app.errorhandler(ValueError)  # includes RegistrationError
    def _bad_request(e):
        return jsonify(error="ValueError", message=str(e)), 400

    @app.before_request
    def _auth():
        if request.path == "/health":
            return None
        if not api_token:  # fail-closed: no token configured → no admin API
            return jsonify(error="Unauthorized", message="admin API not configured"), 503
        header = request.headers.get("Authorization", "")
        presented = header[7:] if header.startswith("Bearer ") else ""
        if presented != api_token:
            return jsonify(error="Unauthorized", message="bad or missing admin token"), 401
        return None

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    @app.post("/elections")
    def register():
        body = request.get_json(force=True)
        config = codecs.dec_config(body["config"])
        lead = int(body.get("dkgLeadTime", dkg_lead_time))
        eid = register_election(dl, config, admin, clock=clock, dkg_lead_time=lead)
        return jsonify(electionId=codecs.enc_bytes(eid)), 200

    @app.post("/elections/<eid>/cancel")
    def cancel(eid):
        cancel_election(dl, bytes.fromhex(eid), admin)
        return "", 204

    return app


def main() -> None:
    """Election Admin — CLI or HTTP service (DESIGN.md §2, §4.1). The committee
    (keyper identities + URLs) is provided in the register config.

    Commands:
      register --config <config.json>   register an election (JSON = §7.2 config envelope)
      cancel   --election-id <hex>       cancel before voting_start
      serve                              run the admin HTTP service (register/cancel)

    Env: ``ADMIN_SIGNING_KEY`` (hex secp256k1 — the adminKey identity, and on the
    blockchain backend the tx sender / on-chain ``adminAddr``), ``GEG_DATA_LAYER`` +
    ``GEG_DATA_LAYER_URL`` (http backends), ``DKG_LEAD_TIME`` (default 0). For
    ``serve``: ``ADMIN_API_TOKEN`` (bearer token; fail-closed if unset), ``ADMIN_HOST``/
    ``ADMIN_PORT`` (default 8300).
    """
    import argparse
    import json
    import logging
    import os
    import time

    from geg.envelopes import codecs
    from geg.services.common.backend import data_layer_for_service

    parser = argparse.ArgumentParser(prog="geg-admin")
    sub = parser.add_subparsers(dest="command", required=True)
    reg = sub.add_parser("register", help="register an election from a config JSON envelope")
    reg.add_argument("--config", required=True)
    can = sub.add_parser("cancel", help="cancel an election before voting_start")
    can.add_argument("--election-id", required=True)
    sub.add_parser("serve", help="run the admin HTTP service")
    args = parser.parse_args()

    admin_key = os.environ["ADMIN_SIGNING_KEY"]
    admin = Signer.from_sk(int(admin_key, 16))
    dl = data_layer_for_service(admin_key)
    lead_time = int(os.environ.get("DKG_LEAD_TIME", "0"))

    if args.command == "register":
        config = codecs.dec_config(json.loads(open(args.config).read()))
        eid = register_election(dl, config, admin, clock=lambda: int(time.time()), dkg_lead_time=lead_time)
        print("registered election", eid.hex())
    elif args.command == "cancel":
        cancel_election(dl, bytes.fromhex(args.election_id.removeprefix("0x")), admin)
        print("cancelled election", args.election_id)
    elif args.command == "serve":
        logging.basicConfig(level=logging.INFO)
        app = build_admin_app(dl, admin, clock=lambda: int(time.time()), dkg_lead_time=lead_time,
                              api_token=os.environ.get("ADMIN_API_TOKEN"))
        app.run(host=os.environ.get("ADMIN_HOST", "0.0.0.0"), port=int(os.environ.get("ADMIN_PORT", "8300")))


if __name__ == "__main__":
    main()
