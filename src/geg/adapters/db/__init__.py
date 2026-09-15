"""Database data-layer adapter.

A microservice exposing the ``ElectionDataLayer`` port over HTTP (the JSON
envelopes), backed by a relational database (Postgres), plus the HTTP client
adapter the services hold. Topology:

    services  →  HttpDataLayerClient (implements ElectionDataLayer)
                    │  HTTP + JSON envelopes
                    ▼
                 Flask microservice (server)  →  PostgresStore  →  Postgres

* :mod:`geg.adapters.db.schema` — relational schema (DDL).
* :mod:`geg.adapters.db.store`  — ``PostgresStore``: the enforcement engine;
  implements the full port contract server-side (ordering, immutability, quorum
  rule, authz via request signatures, idempotency, public reads).
* :mod:`geg.adapters.db.server` — Flask app mapping port methods to routes.
* :mod:`geg.adapters.db.client` — ``HttpDataLayerClient``: the remote adapter.

The store enforces the *same* contract as :class:`geg.adapters.memory.InMemoryDataLayer`
and passes the *same* conformance suite (over HTTP + Postgres).
"""

DEFAULT_DSN = "postgresql://geg:geg@localhost:5433/geg"
