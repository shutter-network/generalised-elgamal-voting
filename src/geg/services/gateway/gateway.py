"""Ballot gateway.

The default user-facing ingest endpoint. Runs the standard admission
verification as a **filter (on by default)** and writes accepted ballots to the
data layer. The filter is for UX (a voter learns immediately that a ballot is
malformed) and spam/storage protection; its accept/reject decision has **no
bearing on tally correctness** — verification is authoritative at tally time, and
a compromised gateway (or a direct-submission path) can inject unverified rows
without affecting the tally.

Duplicate handling is NOT done here (it is evaluated at tally time over the full
ordered list); the gateway only checks single-ballot validity and the voting
window.
"""

from __future__ import annotations

from geg.core.admission import StoredBallot, validate_ballot
from geg.crypto.points import g2_from_compressed
from geg.envelopes.types import BallotEnvelope
from geg.ports.data_layer import ElectionDataLayer, VotingWindowError
from geg.core.state import ElectionState, StateFacts, derive_state


class GatewayRejection(ValueError):
    """Raised when the (on-by-default) gateway filter rejects a ballot."""


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


# --------------------------------------------------------------------------- #
#  HTTP ingest service — the default user-facing ballot endpoint
# --------------------------------------------------------------------------- #

def build_gateway_app(data_layer, *, clock, filter_on: bool = True):
    """Flask ingest app: POST a frontend-built ballot envelope; filtered (on by
    default) then written to the data layer. The filter is UX + spam control — it
    has no bearing on tally correctness."""
    from flask import Flask, jsonify, request

    from geg.envelopes import codecs

    app = Flask(__name__)

    @app.after_request
    def _cors(resp):
        # Browser voter apps POST ballots here directly; allow the JSON preflight.
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    @app.post("/elections/<eid>/ballots")
    def submit(eid):
        election_id = bytes.fromhex(eid)
        try:
            ballot = codecs.dec_ballot(request.get_json(force=True)["ballot"])
        except Exception as exc:  # noqa: BLE001
            return jsonify(error="MALFORMED", message=str(exc)), 400
        try:
            seq = submit_ballot(data_layer, election_id, ballot, clock=clock, filter_on=filter_on)
        except GatewayRejection as rej:
            return jsonify(error="REJECTED", reason=str(rej)), 400
        except VotingWindowError as e:
            # The lifecycle-enforcing backend (chain) rejected the ballot as outside the
            # voting window — e.g. the gateway's own clock and block.timestamp differ by a
            # second at the boundary. A clear client error, not a 500.
            return jsonify(error="OUTSIDE_VOTING_WINDOW", message=str(e)), 400
        except KeyError:
            return jsonify(error="UNKNOWN_ELECTION"), 404
        return jsonify(sequenceNumber=seq), 200

    return app


def main() -> None:
    """Run the ballot gateway against the database data-layer microservice.

    Env: ``GEG_DATA_LAYER``, ``GEG_DATA_LAYER_URL`` (http backends), ``GATEWAY_HOST``/
    ``GATEWAY_PORT``, ``GATEWAY_FILTER`` (default 1 = on). On the blockchain backend
    the gateway submits ballots as its own tx sender, so it needs ``GATEWAY_SIGNING_KEY``
    (hex secp256k1) — ``submitVote`` is authorized by ``msg.sender``.
    """
    import logging
    import os
    import time

    from geg.services.common.backend import data_layer_for_service

    logging.basicConfig(level=logging.INFO)
    dl = data_layer_for_service(os.environ.get("GATEWAY_SIGNING_KEY"))
    filter_on = os.environ.get("GATEWAY_FILTER", "1") == "1"
    port = int(os.environ.get("GATEWAY_PORT", "8200"))
    logging.getLogger("geg.gateway").info("op=start service=gateway port=%d filter=%s", port, "on" if filter_on else "off")
    app = build_gateway_app(dl, clock=lambda: int(time.time()), filter_on=filter_on)
    app.run(host=os.environ.get("GATEWAY_HOST", "0.0.0.0"), port=port)


if __name__ == "__main__":
    main()
