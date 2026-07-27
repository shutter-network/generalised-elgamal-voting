"""Public read-only election API (frontend / external integrators).

A read-only, CORS-enabled HTTP surface over the ``ElectionDataLayer`` **read**
methods, deliberately separate from the internal data-layer service. It is
**backend-blind**: it holds an ``ElectionDataLayer`` (in deployment, an
:class:`~geg.adapters.db.client.HttpDataLayerClient` pointing at the uniform
data-layer service), so it serves identical JSON whether the backend is database
or blockchain — the frontend sees one contract either way.

Responses are the raw §7.2 JSON envelopes today (the same shapes the data-layer
service returns); shaping/enrichment (derived lifecycle state, list summaries,
turnout) can be layered on later without changing the transport.

Only reads are exposed here (public / browser-safe). Writes stay on the
authenticated admin/gateway paths; a future **keyless signed-write relay** (the
frontend wallet signs, this service forwards the signed request — no key held
here) is the natural next addition (auth model B).
"""

from __future__ import annotations

from flask import Flask, jsonify, request

from geg.envelopes import codecs
from geg.ports.data_layer import ElectionDataLayer, ElectionFilter, FinalizedKey

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


def _parse_eid(seg: str) -> bytes:
    """Parse an election id from a URL segment to its canonical 32-byte form.

    **Strict** — exactly the two forms the system emits, nothing else:

    * friendly **decimal** id — ``1``, ``42`` (no prefix, all digits); or
    * canonical **64-char hex** — ``0x0000…0001`` or bare ``0000…0001`` (32 bytes).

    Everything else (short/loose hex like ``0x1`` / ``0x10``, non-64 ``0x`` values)
    is rejected with a ``ValueError`` → HTTP 400, so ``0x`` is never silently read
    as decimal and there are no coincidental matches.
    """
    hex_part = seg[2:] if seg[:2].lower() == "0x" else seg
    if len(hex_part) == 64:
        return bytes.fromhex(hex_part)  # canonical 32-byte hex (0x optional)
    if seg[:2].lower() != "0x" and seg.isdigit():
        n = int(seg)  # friendly sequential id
        if n >> 256:
            raise ValueError(f"election id {seg} out of range (> 2^256)")
        return n.to_bytes(32, "big")
    raise ValueError(f"bad election id {seg!r}: use a decimal id (e.g. 1) or a 64-char hex value")


def _eid_num(election_id: bytes) -> int:
    """Render a 32-byte election id as its decimal (sequential) value."""
    return int.from_bytes(election_id, "big")


def _decimalize_election_ids(obj):
    """Recursively rewrite every ``electionId`` hex field to its decimal id.

    Option A: the public API speaks **decimal** election ids uniformly (top-level,
    lists, and inside every returned envelope); cryptographic byte-strings (keys,
    ciphertexts, proofs, signatures) stay ``0x``-hex. Lossless — a client rebuilds
    the canonical 32 bytes from the integer. (Envelopes returned here are therefore
    display-shaped, not byte-verbatim; the internal data-layer service serves the
    raw hex artifacts for verification.)
    """
    if isinstance(obj, dict):
        return {
            k: (int(v, 16) if k == "electionId" and isinstance(v, str)
                else _decimalize_election_ids(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_decimalize_election_ids(x) for x in obj]
    return obj


def _finalized_key_json(fk: FinalizedKey | None):
    if fk is None:
        return None
    return {
        "pkElection": codecs.enc_bytes(fk.pk_election),
        "committeePKs": [codecs.enc_bytes(p) for p in fk.committee_pks],
    }


def build_api_app(dl: ElectionDataLayer) -> Flask:
    """Build the public read-only API app over any ``ElectionDataLayer``."""
    app = Flask(__name__)

    @app.errorhandler(KeyError)
    def _not_found(e):
        return jsonify(error="KeyError", message=str(e)), 404

    @app.errorhandler(ValueError)
    def _bad_request(e):
        return jsonify(error="ValueError", message=str(e)), 400

    @app.after_request
    def _cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp

    def _eid() -> bytes:
        return _parse_eid(request.view_args["eid"])

    def _reply(payload: dict):
        """Serialize a response, decimalizing every election id (Option A)."""
        return jsonify(_decimalize_election_ids(payload))

    def _int_arg(name: str, default: int) -> int:
        raw = request.args.get(name)
        if raw is None or raw == "":
            return default
        try:
            return int(raw)
        except ValueError:
            raise ValueError(f"query param {name!r} must be an integer")

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    # -- election lifecycle ------------------------------------------------- #

    @app.get("/elections")
    def list_elections():
        admin = request.args.get("admin")
        # Accept the admin address as plain or 0x-prefixed hex (public-API leniency,
        # matching how election ids are parsed in the path).
        filt = ElectionFilter(admin_key=bytes.fromhex(admin.removeprefix("0x"))) if admin else None
        ids = dl.list_elections(filt)
        offset = max(0, _int_arg("offset", 0))
        limit = min(_MAX_LIMIT, max(1, _int_arg("limit", _DEFAULT_LIMIT)))
        page = ids[offset:offset + limit]
        return jsonify(
            electionIds=[_eid_num(e) for e in page],  # friendly decimal (sequential) ids
            total=len(ids), limit=limit, offset=offset,
        )

    @app.get("/elections/<eid>")
    def get_election(eid):
        eid_b = _eid()
        rec = dl.get_election(eid_b)
        return _reply({
            "electionId": _eid_num(eid_b),
            "config": codecs.enc_config(rec.config),
            "cancelled": rec.cancelled,
            "finalizedKey": _finalized_key_json(rec.finalized_key),
        })

    # -- DKG ---------------------------------------------------------------- #

    @app.get("/elections/<eid>/dkg")
    def get_dkg(eid):
        return _reply({"submissions": [codecs.enc_dkg_result(s) for s in dl.get_dkg_submissions(_eid())]})

    @app.get("/elections/<eid>/dkg/finalized")
    def get_finalized(eid):
        return jsonify(finalizedKey=_finalized_key_json(dl.get_finalized_key(_eid())))

    # -- ballots ------------------------------------------------------------ #

    @app.get("/elections/<eid>/ballots")
    def list_ballots(eid):
        # Paginated like /elections (limit/offset). The port's list_ballots(start,
        # count) treats count as a hard cap, so a bare call must pass a real limit —
        # defaulting count to 0 would return nothing. Default to a page, expose total.
        eid_b = _eid()
        total = dl.count_ballots(eid_b)
        offset = max(0, _int_arg("offset", 0))
        limit = min(_MAX_LIMIT, max(1, _int_arg("limit", _DEFAULT_LIMIT)))
        ballots = dl.list_ballots(eid_b, offset, limit)
        return _reply({
            "ballots": [codecs.enc_ballot(b) for b in ballots],
            "total": total, "limit": limit, "offset": offset,
        })

    @app.get("/elections/<eid>/ballots/count")
    def count_ballots(eid):
        return jsonify(count=dl.count_ballots(_eid()))

    # -- tally artifacts ---------------------------------------------------- #

    @app.get("/elections/<eid>/aggregate")
    def get_aggregate(eid):
        agg = dl.get_aggregate(_eid())
        return _reply({"aggregate": codecs.enc_aggregate(agg) if agg else None})

    @app.get("/elections/<eid>/shares")
    def list_shares(eid):
        return _reply({"shares": [codecs.enc_decryption_share(s) for s in dl.list_decryption_shares(_eid())]})

    @app.get("/elections/<eid>/result")
    def get_result(eid):
        res = dl.get_result(_eid())
        return _reply({"result": codecs.enc_result(res) if res else None})

    # -- capability --------------------------------------------------------- #

    @app.get("/capability")
    def capability():
        return jsonify(verifiabilityTier=dl.verifiability_tier())

    return app


def main() -> None:
    """Run the public read-only election API.

    Backend-blind: it reads through the uniform data-layer service, so the same
    process serves the database and blockchain backends unchanged.

    Env: ``GEG_DATA_LAYER_URL`` (the data-layer service it reads through);
    ``API_HOST`` / ``API_PORT`` (default 8500).
    """
    import logging
    import os

    from geg.adapters.db.client import HttpDataLayerClient

    logging.basicConfig(level=logging.INFO)
    dl = HttpDataLayerClient(os.environ["GEG_DATA_LAYER_URL"])
    app = build_api_app(dl)
    app.run(host=os.environ.get("API_HOST", "0.0.0.0"), port=int(os.environ.get("API_PORT", "8500")))


if __name__ == "__main__":
    main()
