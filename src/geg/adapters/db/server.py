"""Database backend of the uniform data-layer service.

The HTTP surface is now backend-agnostic and lives in
:mod:`geg.services.data_layer` (:func:`build_app` maps the ``ElectionDataLayer``
port onto routes for *any* adapter). This module re-exports ``build_app`` for
backward compatibility and provides the Postgres-backed entrypoint
(``python -m geg.adapters.db.server``), equivalent to running the uniform service
with ``GEG_DATA_LAYER=database``.
"""

from __future__ import annotations

from geg.services.data_layer import build_app

__all__ = ["build_app", "main"]


def main() -> None:
    """Run the data-layer microservice against Postgres.

    Env: ``GEG_DATA_LAYER_DSN`` (Postgres DSN), ``DATA_LAYER_HOST`` / ``DATA_LAYER_PORT``.
    """
    import os

    from geg.services.data_layer import main as _main

    os.environ.setdefault("GEG_DATA_LAYER", "database")
    _main()


if __name__ == "__main__":
    main()
