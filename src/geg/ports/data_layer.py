"""``ElectionDataLayer`` — the single storage abstraction.

The method set is a proven storage surface, generalised so that no method
assumes a chain. All artifacts are stored and returned as opaque, self-verifying
envelopes (:mod:`geg.envelopes`); the data layer never interprets crypto beyond
the two rules noted below.

Contract of the port:

* **Availability only.** The data layer is untrusted for integrity. It performs no proof verification.
* **Ordering.** :meth:`ElectionDataLayer.list_ballots` returns ballots in a
  stable total order with monotonic sequence numbers, so ``duplicate_policy`` is
  deterministically reproducible by every auditor. (Chain: transaction order;
  database: an append sequence.)
* **Immutability.** Election config is immutable after ``voting_start``. Artifacts
  are append-only; :meth:`submit_decryption_share` is idempotent on
  ``(election_id, keyper_index, candidate)``. Exception: a keyper's
  :meth:`submit_aggregate` is **overridable until the aggregate quorum finalizes**,
  then frozen (see that method).
* **Quorum rules** (the places the data layer is not dumb): (1) the finalized *key*
  exists iff ≥ ``t + 1`` distinct registered keypers submitted byte-identical
  ``(pk_election, committee_pks)``; (2) the canonical *aggregate* exists iff ≥
  ``t + 1`` keypers submitted a byte-identical aggregate artifact. Both deterministic
  and publicly re-checkable from the stored submissions.
* **Authorization matrix** (defense-in-depth against spam, not a trust anchor):
  writes are checked against identities in the election config; all reads are
  public. config/cancel → ``admin_key``; DKG results, decryption shares **and the
  aggregate** → registered keypers; ballots → ``gateway_keys`` (or open where direct
  submission is enabled); result → ``result_publisher_key``.
* **Capability tiers.** :meth:`verifiability_tier` returns 0 in v1 (availability
  only). Future tiers (inclusion receipts, append-only proofs) extend the port
  without breaking it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from geg.core.config import ElectionConfig
from geg.envelopes.types import (
    AggregateArtifact,
    BallotEnvelope,
    DecryptionShareEnvelope,
    DKGResultSubmission,
    ResultArtifact,
    StoredBallot,
)


@dataclass(frozen=True)
class FinalizedKey:
    """The finalized election key: joint mpk plus per-keyper committee PKs."""

    pk_election: bytes  # G2
    committee_pks: tuple[bytes, ...]  # each G2


@dataclass(frozen=True)
class ElectionRecord:
    """An election's stored config plus finalization facts.

    Returned by :meth:`ElectionDataLayer.get_election`. State (``Registered``,
    ``Voting``, ``Tallying`` …) is **not** stored here — it is derived from these
    facts and the current time by the state-derivation function. ``cancelled`` records only whether a cancellation fact exists.
    """

    config: ElectionConfig
    cancelled: bool
    finalized_key: FinalizedKey | None
    # Advisory, recoverable: the coordinator abandoned the tally after exhausting its
    # attempts (too few keypers to reach the quorum). Overlays `Tallying` in state
    # derivation; a published result supersedes it. Cleared when the coordinator resumes.
    tally_stalled: bool = False


@dataclass(frozen=True)
class ElectionFilter:
    """Optional filter for :meth:`ElectionDataLayer.list_elections`."""

    admin_key: bytes | None = None


class WriteAuthorizationError(PermissionError):
    """Raised when a write is not signed by an identity authorized in the config."""


class ImmutabilityError(RuntimeError):
    """Raised on an attempt to mutate config after ``voting_start``."""


class VotingWindowError(RuntimeError):
    """Raised when a write is attempted at the wrong point in the voting lifecycle:
    a ballot before ``voting_start`` / after ``voting_end``, or a tally write (aggregate,
    decryption share, result) before ``voting_end``. Only lifecycle-enforcing backends
    (the chain) raise it — availability-only backends accept the write and verification
    is authoritative at tally time."""


class ElectionDataLayer(ABC):
    """Storage port. Availability-only; every stored artifact is self-verifying."""

    # --- election lifecycle ------------------------------------------------- #

    @abstractmethod
    def register_election(self, config: ElectionConfig, admin_sig: bytes) -> bytes:
        """Register a new election; return its ``election_id``.

        Authorized writer: ``config.admin_key`` (verified via ``admin_sig``).
        """

    @abstractmethod
    def cancel_election(self, election_id: bytes, admin_sig: bytes) -> None:
        """Record a cancellation. Rejected once ``now >= voting_start``.

        Authorized writer: the election's ``admin_key``.
        """

    @abstractmethod
    def get_election(self, election_id: bytes) -> ElectionRecord:
        """Return config + finalization facts. Public read."""

    @abstractmethod
    def list_elections(self, filter: ElectionFilter | None = None) -> list[bytes]:
        """Return matching election ids. Public read."""

    # --- DKG ---------------------------------------------------------------- #

    @abstractmethod
    def submit_dkg_result(
        self,
        election_id: bytes,
        pk_election: bytes,
        committee_pks: list[bytes],
        keyper_sig: bytes,
    ) -> None:
        """Submit one keyper's DKG result vote (append-only per keyper).

        Authorized writer: a registered keyper. Finalization is derived by the
        quorum rule, never asserted by the submitter.
        """

    @abstractmethod
    def get_dkg_submissions(self, election_id: bytes) -> list[DKGResultSubmission]:
        """Return all signed DKG result submissions. Public read."""

    @abstractmethod
    def get_finalized_key(self, election_id: bytes) -> FinalizedKey | None:
        """Return the finalized key iff the quorum rule is met, else ``None``.

        Public read; deterministically re-checkable from
        :meth:`get_dkg_submissions`.
        """

    # --- ballots ------------------------------------------------------------ #

    @abstractmethod
    def submit_ballot(self, election_id: bytes, ballot: BallotEnvelope) -> int:
        """Append a ballot; return its monotonic sequence number.

        Authorized writer: a ``gateway_key`` (or open where direct submission is
        enabled). No proof verification here — ballots are self-verifying and
        verification is authoritative at tally time.

        **Voting-window gate.** Every backend rejects a ballot written outside the
        open voting window with :class:`VotingWindowError`, using the same gate set
        the chain contract's ``submitVote`` applies (not cancelled, DKG finalized,
        ``voting_start <= now < voting_end`` — i.e. derived state ``Voting``). This
        is defense in depth, not the integrity boundary: the authoritative check is
        the ``OUT_OF_WINDOW`` reason at tally time, re-derived from the
        ``submitted_at`` that :meth:`list_ballots` returns.
        """

    @abstractmethod
    def list_ballots(self, election_id: bytes, start: int, count: int) -> list[StoredBallot]:
        """Return stored ballots in stable total order from ``start``. Public read.

        Each row carries its ``sequence_number`` and the adapter's authoritative
        ``submitted_at`` receive time alongside the envelope, so the tally-time
        ``OUT_OF_WINDOW`` check is re-derivable from a public read instead of
        depending on an ingress having filtered correctly.
        """

    @abstractmethod
    def count_ballots(self, election_id: bytes) -> int:
        """Return the number of stored ballots. Public read."""

    # --- tally artifacts ---------------------------------------------------- #

    @abstractmethod
    def submit_aggregate(
        self, election_id: bytes, aggregate: AggregateArtifact, keyper_sig: bytes
    ) -> None:
        """Submit one keyper's aggregate (**mutable per keyper until finalized**).

        Authorized writer: a registered keyper, which content-signs the **full**
        artifact (aggregates + admitted set + exclusions + total weight). The
        aggregate is *not* asserted canonical by the submitter — it becomes canonical
        by the quorum rule (see :meth:`get_aggregate`). Since admission + aggregation
        are deterministic, honest keypers submit byte-identical artifacts.

        Unlike :meth:`submit_dkg_result` (append-only), a keyper **may override** its
        own earlier submission while the aggregate is not yet canonical — aggregation
        is a deterministic re-derivation, so a keyper that submitted a wrong/stale
        artifact can correct it and let honest keypers re-converge on the quorum. Once
        the ``t + 1`` quorum is reached the aggregate is **frozen**: any further
        submission that would change it is rejected (:class:`ImmutabilityError`). An
        identical resend of a keyper's current submission is always a no-op.
        """

    @abstractmethod
    def get_aggregate(self, election_id: bytes) -> AggregateArtifact | None:
        """Return the canonical aggregate iff the quorum rule is met, else ``None``.

        Canonical iff ≥ ``t + 1`` distinct registered keypers submitted a
        byte-identical aggregate. Public read; deterministically re-checkable.
        """

    @abstractmethod
    def submit_decryption_share(
        self, election_id: bytes, share: DecryptionShareEnvelope, keyper_sig: bytes
    ) -> None:
        """Submit a keyper's decryption shares. Authorized: a registered keyper.

        Idempotent on ``(election_id, keyper_index, candidate)`` — re-sending
        identical shares is a no-op; shares for a *different* ciphertext under the
        same key are rejected.
        """

    @abstractmethod
    def list_decryption_shares(self, election_id: bytes) -> list[DecryptionShareEnvelope]:
        """Return all submitted decryption shares. Public read."""

    @abstractmethod
    def publish_result(
        self, election_id: bytes, result: ResultArtifact, result_publisher_sig: bytes
    ) -> None:
        """Publish the final result. Authorized: ``result_publisher_key``."""

    @abstractmethod
    def get_result(self, election_id: bytes) -> ResultArtifact | None:
        """Return the published result, or ``None``. Public read."""

    @abstractmethod
    def set_tally_stalled(self, election_id: bytes, stalled: bool, sig: bytes) -> None:
        """Set/clear the advisory *tally stalled* flag (surfaced in ``get_election`` and the
        derived state). **Direction-split, one-directional per party:**

        - ``stalled=True`` (**mark**) — authorized by ``result_publisher_key`` (the coordinator),
          op ``"tally_stall"``; only after ``voting_end`` and only if no result exists.
        - ``stalled=False`` (**clear / retry**) — authorized by ``admin_key`` (the election
          admin), op ``"tally_resume"``.

        So the coordinator is the sole party that can stall, and the admin is the sole party
        that can clear (the retry). Recoverable: a published result supersedes it (→ Complete),
        and a coordinator restart does **not** clear it (the flag is authoritative)."""

    # --- capability --------------------------------------------------------- #

    @abstractmethod
    def verifiability_tier(self) -> int:
        """Advertised verifiability tier. v1 adapters return 0."""
