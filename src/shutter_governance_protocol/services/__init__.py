"""Services / actors — thin orchestration over the deep modules,
organized one **domain package** per actor. Each package colocates that domain's
modules and re-exports its public API; deployable ones expose ``__main__`` so
``python -m shutter_governance_protocol.services.<domain>`` runs them.

* :mod:`shutter_governance_protocol.services.keyper` — DKG participation + precondition-guarded decryption; the
  HTTP keyper process, token bootstrap, and encrypted state.
* :mod:`shutter_governance_protocol.services.coordinator` — the single keyper-facing orchestrator: DKG
  watcher/driver **and** tally driver (trigger aggregate → quorum → decrypt →
  recover + publish result) + keyper-write relay (``dkg_coordinator`` holds the
  ceremony primitives).
* :mod:`shutter_governance_protocol.services.tally_aggregator` — tally *library*: ``finalize`` (recover +
  publish the result, called by the coordinator) plus the in-process test harness.
* :mod:`shutter_governance_protocol.services.gateway` — ballot admission filter (library; the ingest HTTP
  endpoint is hosted on :mod:`shutter_governance_protocol.services.api`).
* :mod:`shutter_governance_protocol.services.admin` — sole writer of election config (CLI + HTTP).
* :mod:`shutter_governance_protocol.services.auditor` — re-verifies an election from public reads.
* :mod:`shutter_governance_protocol.services.data_layer` — the uniform data-layer HTTP service.
* :mod:`shutter_governance_protocol.services.common` — shared helpers (backend selection).
"""
