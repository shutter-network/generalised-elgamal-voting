"""Quorum resolution shared by the off-chain data-layer adapters.

One place that answers "did an artifact reach the keyper quorum, and is the answer
unambiguous?", so the memory and DB adapters cannot drift apart on it.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeVar

from geg.ports.data_layer import QuorumConflictError

T = TypeVar("T")


def resolve_unique(
    groups: Iterable[tuple[T, set[int]]],
    needed: int,
    *,
    artifact: str,
    election_id: bytes,
) -> T | None:
    """The single artifact that reached ``needed`` keypers, or ``None`` if none has.

    ``groups`` pairs each distinct artifact with the set of keyper indices that submitted
    it. Raises :class:`QuorumConflictError` if more than one reached the quorum — returning
    the first would make the outcome depend on iteration order (see the error's docstring).
    """
    finalized = [(value, keypers) for value, keypers in groups if len(keypers) >= needed]
    if len(finalized) > 1:
        detail = "; ".join(f"keypers {sorted(kps)}" for _, kps in finalized)
        raise QuorumConflictError(
            f"{artifact}: {len(finalized)} distinct artifacts each reached the quorum of "
            f"{needed} for election {election_id.hex()} ({detail}). The committee has "
            f"split; refusing to pick one by iteration order."
        )
    return finalized[0][0] if finalized else None
