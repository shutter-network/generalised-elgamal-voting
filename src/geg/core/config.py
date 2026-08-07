"""Election configuration and lifecycle enums.

The election-configuration table. The config is
registered once by the admin service and is **immutable after ``voting_start``**
(the data-layer adapter enforces this: free on the contract adapter, mandatory
server-side on the database adapter).

Every field here is a pure datum; nothing in this module performs I/O or crypto.
Identities (``eligibility_key``, ``result_publisher_key``, ``gateway_keys``,
``admin_key``, and each keyper's signing identity) are opaque ``bytes`` — the
data-layer adapter decides how to interpret them (a 20-byte Ethereum address on
the chain adapter, a 48-byte compressed-G1 key on a signature-checking database
adapter, etc.). The core protocol only compares them for equality.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Mode(str, Enum):
    """Budget constraint over the per-ballot vote vector."""

    EXACT = "exact"  # sum(votes) == budget
    AT_MOST = "atMost"  # sum(votes) <= budget   (conformance level 2)


class Variant(str, Enum):
    """Per-candidate validity-proof construction."""

    A = "A"  # (B+1)-branch OR proof per candidate      (conformance level 1)
    B = "B"  # bit-decomposition proofs per candidate   (conformance level 2)


class DuplicatePolicy(str, Enum):
    """How repeated ballots for one pseudonym are resolved at tally time.

    Evaluated over the data layer's stable total order, so the
    outcome is reproducible by any auditor.
    """

    FIRST_WINS = "first-wins"
    LAST_WINS = "last-wins"


@dataclass(frozen=True)
class Threshold:
    """(t, n): any ``t + 1`` of ``n`` keypers can decrypt."""

    t: int
    n: int

    def __post_init__(self) -> None:
        if self.n < 1:
            raise ValueError("The committee size (n) must be at least 1.")
        if not (0 <= self.t < self.n):
            raise ValueError("The threshold must satisfy 0 <= t < n (you need t+1 keypers to decrypt).")


@dataclass(frozen=True)
class KeyperIdentity:
    """One committee member: a signing identity plus a P2P URL.

    ``signing_key`` is the opaque identity the data layer checks DKG-result,
    aggregate, and decryption-share writes against; ``url`` is where the
    coordinator reaches this keyper over HTTP.
    """

    signing_key: bytes
    url: str


@dataclass(frozen=True)
class ElectionConfig:
    """Full immutable election configuration.

    Superset of the on-chain ``ElectionConfigView``: this generalised config
    adds ``mode``, ``variant``, ``weighted``, ``max_weight``, ``duplicate_policy``,
    per-keyper URLs, and the explicit authorization
    identities (``eligibility_key``, ``result_publisher_key``, ``gateway_keys``,
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
    threshold: Threshold
    keypers: tuple[KeyperIdentity, ...]  # n keyper identities + URLs
    eligibility_key: bytes  # public key attestations must verify against
    result_publisher_key: bytes  # identity authorized to publish aggregate + result
    gateway_keys: tuple[bytes, ...]  # authorized ballot writers (empty = open writes)
    admin_key: bytes  # identity authorized to register/cancel
    protocol_version: str  # crypto suite + wire format version

    def __post_init__(self) -> None:
        if self.num_candidates < 1:
            raise ValueError("There must be at least one candidate.")
        if self.budget < 1:
            raise ValueError("The budget must be at least 1.")
        if self.max_weight < 1:
            raise ValueError("Max weight must be at least 1.")
        if not self.weighted and self.max_weight != 1:
            raise ValueError("An unweighted election must have a max weight of 1 (enable weighting to allow higher weights).")
        if self.voting_end <= self.voting_start:
            raise ValueError("Voting end must be after voting start.")
        if len(self.keypers) != self.threshold.n:
            raise ValueError(
                f"The committee needs exactly {self.threshold.n} keypers, but got {len(self.keypers)}."
            )
        # The committee must be n *distinct* members. Two entries with the same
        # signing key are the same keyper (e.g. two URLs that resolve to one keyper's
        # /status identity) and would corrupt the t-of-n threshold — reject
        # authoritatively here, independent of any frontend check. (URLs are not
        # deduped: in-process deployments leave them empty; duplicate-URL rejection is
        # a frontend UX guard.)
        keys = [k.signing_key for k in self.keypers]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate keyper: each committee member must be a distinct wallet.")
