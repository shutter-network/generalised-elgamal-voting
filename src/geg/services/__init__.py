"""Services / actors (DESIGN.md §2) — thin orchestration over the deep modules,
organized one **domain package** per actor. Each package colocates that domain's
modules and re-exports its public API; deployable ones expose ``__main__`` so
``python -m geg.services.<domain>`` runs them.

* :mod:`geg.services.keyper` — DKG participation + §8.2-guarded decryption; the
  HTTP keyper process, token bootstrap, and encrypted state.
* :mod:`geg.services.coordinator` — DKG watcher/driver + keyper-write relay
  (``dkg_coordinator`` holds the ceremony primitives).
* :mod:`geg.services.tally_aggregator` — admit → aggregate → trigger → recover.
* :mod:`geg.services.gateway` — ballot ingest with an on-by-default filter.
* :mod:`geg.services.admin` — sole writer of election config (CLI + HTTP).
* :mod:`geg.services.auditor` — re-verifies an election from public reads.
* :mod:`geg.services.data_layer` — the uniform data-layer HTTP service.
* :mod:`geg.services.common` — shared helpers (backend selection).
"""
