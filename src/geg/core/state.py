"""Derived election lifecycle state (DESIGN.md §4.2).

Election state is **derived, never stored**: a pure function of the facts in the
data layer and the current time. Every service and every auditor uses this same
function, so no service owns transitions — they are all watchers. The voting
interval is half-open ``[voting_start, voting_end)``: a ballot at exactly
``voting_end`` is out of window.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from geg.core.config import ElectionConfig


class ElectionState(str, Enum):
    # Terminal states.
    CANCELLED = "Cancelled"  # cancellation recorded (only possible before voting_start)
    COMPLETE = "Complete"  # result published
    VOID = "Void"  # now >= tally_deadline and no result
    DKG_FAILED = "DKGFailed"  # now >= voting_start and key not finalized
    # Live states.
    REGISTERED = "Registered"  # config exists, key not finalized, now < voting_start
    KEY_READY = "KeyReady"  # key finalized, now < voting_start
    VOTING = "Voting"  # key finalized, voting_start <= now < voting_end
    TALLYING = "Tallying"  # key finalized, now >= voting_end, no result, now < tally_deadline


@dataclass(frozen=True)
class StateFacts:
    """The data-layer facts state derivation depends on (DESIGN.md §4.2)."""

    cancelled: bool  # a cancellation fact exists
    key_finalized: bool  # the DKG finalization quorum rule is met
    result_published: bool  # a result artifact exists


def derive_state(config: ElectionConfig, facts: StateFacts, now: int) -> ElectionState:
    """Map ``(config, facts, now)`` to a lifecycle state (DESIGN.md §4.2, normative).

    The order below is the normative derivation: terminal outcomes are resolved
    before live states.
    """
    # Terminal: cancellation (only ever recorded before voting_start).
    if facts.cancelled:
        return ElectionState.CANCELLED
    # Terminal: a published result wins over everything else.
    if facts.result_published:
        return ElectionState.COMPLETE
    # Terminal: no result by the tally deadline.
    if now >= config.tally_deadline:
        return ElectionState.VOID
    # Terminal: no finalized key by the time voting opens.
    if now >= config.voting_start and not facts.key_finalized:
        return ElectionState.DKG_FAILED

    # Live states (key finalization + the half-open voting window).
    if not facts.key_finalized:
        # now < voting_start guaranteed here (else DKGFailed above).
        return ElectionState.REGISTERED
    if now < config.voting_start:
        return ElectionState.KEY_READY
    if now < config.voting_end:
        return ElectionState.VOTING
    return ElectionState.TALLYING


def is_voting_open(config: ElectionConfig, now: int) -> bool:
    """Half-open voting-window predicate: ``voting_start <= now < voting_end``."""
    return config.voting_start <= now < config.voting_end
