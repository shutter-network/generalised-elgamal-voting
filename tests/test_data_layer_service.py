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
from geg.services.data_layer import build_app


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
