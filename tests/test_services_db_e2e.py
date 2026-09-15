"""Full election through the services against the DATABASE backend (HTTP + Postgres).

The same services that ran on the in-memory adapter in test_services_e2e.py run
here unchanged over ``HttpDataLayerClient`` → Flask microservice → Postgres. This
is the payoff of the port: swap the backend by configuration, the protocol / wire
format / audit procedure are identical. Skips if no Postgres is reachable.
"""

from __future__ import annotations

import os
import threading

import pytest

from conftest import ManualClock, build_full_env

from geg.adapters.db import DEFAULT_DSN
from geg.services import admin, auditor
from geg.services.coordinator import dkg_coordinator as coord
from geg.services import tally_aggregator as agg
from geg.services.gateway import submit_ballot

DSN = os.environ.get("GEG_TEST_DSN", DEFAULT_DSN)
DKG_LEAD_TIME = 100


@pytest.fixture
def db_full_env():
    psycopg = pytest.importorskip("psycopg")
    from werkzeug.serving import make_server

    from geg.adapters.db.client import HttpDataLayerClient
    from geg.adapters.db.server import build_app
    from geg.adapters.db.store import PostgresStore

    clock = ManualClock(0)
    try:
        store = PostgresStore(DSN, clock=clock)
        store.init_schema()
    except psycopg.OperationalError as exc:
        pytest.skip(f"Postgres not reachable at {DSN}: {exc}")
    store.truncate_all()

    srv = make_server("127.0.0.1", 0, build_app(store))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        client = HttpDataLayerClient(f"http://127.0.0.1:{srv.server_port}")
        yield build_full_env(client, clock)
    finally:
        srv.shutdown()
        thread.join()


def test_full_weighted_election_over_postgres(db_full_env):
    fe = db_full_env
    admin.register_election(fe.dl, fe.config, fe.admin.sign_register(fe.config),
                            admin_identity=fe.admin.identity, clock=fe.clock, dkg_lead_time=DKG_LEAD_TIME)
    assert coord.ensure_dkg(
        fe.config.election_id, fe.keypers, fe.dl, n=fe.n, t=fe.t, clock=fe.clock, deadline=fe.config.voting_start
    )

    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([3, 0, 0], b"\x01" * 32, weight=2), clock=fe.clock, gateway_signer=fe.gateway)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([0, 3, 0], b"\x02" * 32, weight=5), clock=fe.clock, gateway_signer=fe.gateway)

    fe.clock.set(2_500)
    result = agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)
    assert list(result.totals) == [6, 15, 0]

    # Auditor re-verifies the whole election reading only from Postgres via HTTP.
    report = auditor.audit(fe.dl, fe.config.election_id)
    assert report.ok, report.discrepancies


def test_result_persists_across_client_reconnect(db_full_env):
    """Data is durably in Postgres: a fresh client reads the published result."""
    from geg.adapters.db.client import HttpDataLayerClient

    fe = db_full_env
    admin.register_election(fe.dl, fe.config, fe.admin.sign_register(fe.config),
                            admin_identity=fe.admin.identity, clock=fe.clock, dkg_lead_time=DKG_LEAD_TIME)
    coord.ensure_dkg(fe.config.election_id, fe.keypers, fe.dl, n=fe.n, t=fe.t, clock=fe.clock, deadline=fe.config.voting_start)
    fe.clock.set(1_500)
    submit_ballot(fe.dl, fe.config.election_id, fe.voter_ballot([1, 1, 1], b"\x01" * 32), clock=fe.clock, gateway_signer=fe.gateway)
    fe.clock.set(2_500)
    agg.run_tally(fe.dl, fe.config.election_id, fe.result_publisher, fe.keypers, clock=fe.clock)

    fresh = HttpDataLayerClient(fe.dl._base)  # new client, same server/DB
    result = fresh.get_result(fe.config.election_id)
    assert result is not None and list(result.totals) == [1, 1, 1]
