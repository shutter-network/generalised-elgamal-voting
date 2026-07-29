"""Tally library: recover + publish the result (``finalize``) and the in-process
test harness (``run_tally``/``trigger_*``). The coordinator (``geg.services.coordinator``)
drives the tally as the single keyper-facing orchestrator and imports ``finalize`` here."""
from geg.services.tally_aggregator.tally_aggregator import (
    TallyError, finalize, run_tally, trigger_aggregate, trigger_keypers,
)

__all__ = ["run_tally", "trigger_aggregate", "finalize", "trigger_keypers", "TallyError"]
