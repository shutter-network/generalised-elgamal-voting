"""Election configuration and lifecycle enums.

Implements the election-configuration table of DESIGN.md §4.1. The config is
registered once by the admin service and is **immutable after ``voting_start``**
(the data-layer adapter enforces this: free on the contract adapter, mandatory
server-side on the database adapter).

Every field here is a pure datum; nothing in this module performs I/O or crypto.
Identities (``eligibility_key``, ``aggregator_key``, ``gateway_keys``,
``admin_key``, and each keyper's signing identity) are opaque ``bytes`` — the
data-layer adapter decides how to interpret them (a 20-byte Ethereum address on
the chain adapter, a 48-byte compressed-G1 key on a signature-checking database
adapter, etc.). The core protocol only compares them for equality.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Mode(str, Enum):
    """Budget constraint over the per-ballot vote vector (DESIGN.md §4.1, §6.1)."""

    EXACT = "exact"  # sum(votes) == budget
    AT_MOST = "atMost"  # sum(votes) <= budget   (conformance level 2)


class Variant(str, Enum):
    """Per-candidate validity-proof construction (DESIGN.md §6.1)."""

    A = "A"  # (B+1)-branch OR proof per candidate      (conformance level 1)
    B = "B"  # bit-decomposition proofs per candidate   (conformance level 2)


class DuplicatePolicy(str, Enum):
    """How repeated ballots for one pseudonym are resolved at tally time.

    Evaluated over the data layer's stable total order (DESIGN.md §6.2), so the
    outcome is reproducible by any auditor.
    """

    FIRST_WINS = "first-wins"
    LAST_WINS = "last-wins"


@dataclass(frozen=True)
class Threshold:
    """(t, n): any ``t + 1`` of ``n`` keypers can decrypt (DESIGN.md §4.1)."""

    t: int
    n: int

    def __post_init__(self) -> None:
        if self.n < 1:
            raise ValueError("threshold.n must be >= 1")
        if not (0 <= self.t < self.n):
            raise ValueError("threshold requires 0 <= t < n")


@dataclass(frozen=True)
class KeyperIdentity:
    """One committee member: a signing identity plus a P2P endpoint (DESIGN.md §4.1).

    ``signing_key`` is the opaque identity the data layer checks DKG-result and
    decryption-share writes against; ``endpoint`` is where the DKG coordinator and
    the aggregator reach this keyper over HTTP.
    """

    signing_key: bytes
    endpoint: str


@dataclass(frozen=True)
class ElectionConfig:
    """Full immutable election configuration (DESIGN.md §4.1).

    Superset of the on-chain ``ElectionConfigView`` (see
    ``thresholdELGamal/src/eth_client.py::get_election``): this generalised config
    adds ``mode``, ``variant``, ``weighted``, ``max_weight``, ``duplicate_policy``,
    ``tally_deadline``, per-keyper endpoints, and the explicit authorization
    identities (``eligibility_key``, ``aggregator_key``, ``gateway_keys``,
    ``admin_key``) plus ``protocol_version``.
    """

    election_id: bytes  # globally unique (bytes32)
    num_candidates: int  # length of the vote vector
    budget: int  # B, the per-ballot vote budget
    mode: Mode
    variant: Variant
    weighted: bool  # whether attested weights other than 1 are permitted
    max_weight: int  # upper bound the eligibility service may attest per ballot
    duplicate_policy: DuplicatePolicy
    voting_start: int  # absolute unix timestamp (seconds)
    voting_end: int  # absolute unix timestamp (seconds)
    tally_deadline: int  # after this, an election without a result is Void
    threshold: Threshold
    keypers: tuple[KeyperIdentity, ...]  # n keyper identities + endpoints
    eligibility_key: bytes  # public key attestations must verify against
    aggregator_key: bytes  # identity authorized to publish aggregate + result
    gateway_keys: tuple[bytes, ...]  # authorized ballot writers (empty = open writes)
    admin_key: bytes  # identity authorized to register/cancel
    protocol_version: str  # crypto suite + wire format version (DESIGN.md §7)

    def __post_init__(self) -> None:
        if self.num_candidates < 1:
            raise ValueError("num_candidates must be >= 1")
        if self.budget < 1:
            raise ValueError("budget must be >= 1")
        if self.max_weight < 1:
            raise ValueError("max_weight must be >= 1")
        if not self.weighted and self.max_weight != 1:
            raise ValueError("unweighted elections must have max_weight == 1")
        if self.voting_end <= self.voting_start:
            raise ValueError("voting_end must be after voting_start")
        if self.tally_deadline < self.voting_end:
            raise ValueError("tally_deadline must be >= voting_end")
        if len(self.keypers) != self.threshold.n:
            raise ValueError(
                f"expected {self.threshold.n} keypers, got {len(self.keypers)}"
            )
