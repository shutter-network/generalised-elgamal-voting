"""Run the shared conformance suite against the uniform data-layer HTTP service
wrapping the in-memory backend (DESIGN.md §5.1, §7.2).

The same :func:`geg.services.data_layer.build_app` that fronts Postgres in
production also fronts :class:`~geg.adapters.memory.InMemoryDataLayer` here,
driven through the exact ``HttpDataLayerClient`` services hold. Passing the full
conformance suite over HTTP + memory proves the service is genuinely
backend-agnostic — the ``GEG_DATA_LAYER`` selector swaps the backend and nothing
above the port changes. No external infra required (unlike the Postgres run), so
this is the always-on proof of the uniform service.
"""

from __future__ import annotations

import threading

import pytest

from conformance import DataLayerConformance, ManualClock, SignatureBackend

from geg.adapters.db.client import HttpDataLayerClient
from geg.adapters.memory import InMemoryDataLayer
from geg.envelopes.types import Attestation, BallotEnvelope, Ciphertext
from geg.ports.data_layer import VotingWindowError
from geg.services.data_layer import build_app


def test_voting_window_error_round_trips_over_http():
    """A backend ``VotingWindowError`` (only chain raises it in practice) must survive
    the HTTP hop as its typed port exception: service → 422 → client → VotingWindowError.
    Proven here over the memory backend by making its write raise the error."""
    from werkzeug.serving import make_server

    clock = ManualClock(0)
    dl = InMemoryDataLayer(clock=clock)
    dl.submit_ballot = lambda *_a, **_k: (_ for _ in ()).throw(VotingWindowError("VotingClosed(...)"))
    eid = (1).to_bytes(32, "big")
    att = Attestation(election_id=eid, pseudonym=b"\x22" * 32, vk=b"\x33" * 48, weight=1, signature=b"\x44" * 80)
    ballot = BallotEnvelope(
        election_id=eid, pseudonym=b"\x22" * 32, vk=b"\x33" * 48,
        ciphertexts=tuple(Ciphertext(c1=b"\x01" * 96, c2=b"\x02" * 96) for _ in range(3)),
        zk_proof=b"\x01\x02\x03", voter_signature=b"\x55" * 80, attestation=att,
    )
    srv = make_server("127.0.0.1", 0, build_app(dl))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        client = HttpDataLayerClient(f"http://127.0.0.1:{srv.server_port}")
        with pytest.raises(VotingWindowError):
            client.submit_ballot(eid, ballot)
    finally:
        srv.shutdown()
        thread.join()


class TestUniformServiceOverMemory(DataLayerConformance):
    @pytest.fixture
    def backend(self):
        from werkzeug.serving import make_server

        clock = ManualClock(0)
        dl = InMemoryDataLayer(clock=clock)
        srv = make_server("127.0.0.1", 0, build_app(dl))
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            client = HttpDataLayerClient(f"http://127.0.0.1:{srv.server_port}")
            yield SignatureBackend(client, clock)
        finally:
            srv.shutdown()
            thread.join()
