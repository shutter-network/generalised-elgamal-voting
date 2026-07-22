"""Run the shared conformance suite against the database adapter (HTTP + Postgres).

Spins the Flask microservice in a background thread against the dedicated
Postgres (docker compose up), and drives it through ``HttpDataLayerClient`` — the
exact object services hold when the database backend is selected. Skips if no
Postgres is reachable (e.g. CI without the container).

    docker compose up -d      # start the dedicated Postgres first
"""

from __future__ import annotations

import os
import threading

import pytest

from conformance import DataLayerConformance, ManualClock, SignatureBackend

from geg.adapters.db import DEFAULT_DSN

DSN = os.environ.get("GEG_TEST_DSN", DEFAULT_DSN)


@pytest.fixture(scope="module")
def _pg_ready():
    """Connect once and create the schema; skip the whole module if unreachable."""
    psycopg = pytest.importorskip("psycopg")
    from geg.adapters.db.store import PostgresStore

    try:
        store = PostgresStore(DSN)
        store.init_schema()
    except psycopg.OperationalError as exc:
        pytest.skip(f"Postgres not reachable at {DSN}: {exc}")
    return DSN


class TestPostgresConformance(DataLayerConformance):
    @pytest.fixture
    def backend(self, _pg_ready):
        from werkzeug.serving import make_server

        from geg.adapters.db.client import HttpDataLayerClient
        from geg.adapters.db.server import build_app
        from geg.adapters.db.store import PostgresStore

        clock = ManualClock(0)
        store = PostgresStore(_pg_ready, clock=clock)
        store.truncate_all()  # isolate each test
        srv = make_server("127.0.0.1", 0, build_app(store))
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            client = HttpDataLayerClient(f"http://127.0.0.1:{srv.server_port}")
            yield SignatureBackend(client, clock)
        finally:
            srv.shutdown()
            thread.join()
