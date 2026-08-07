"""In-memory ``ElectionDataLayer`` — the reference adapter.

Single-process, for tests, demos, and as the executable definition of the port
semantics. Enforces the full port contract: stable total ballot ordering with
monotonic sequence numbers, config immutability after ``voting_start``,
append-only artifacts, the DKG finalization quorum rule, the write-authorization
matrix (via :mod:`geg.authz`), idempotent share submission, public reads, and
``verifiability_tier() == 0``.

Time is injected via a ``clock`` callable so immutability and cancellation
windows are testable without wall-clock dependence (matching the "authoritative
time source is the adapter's" rule). The database adapter will
enforce the same contract server-side; both are correct iff they pass the
conformance suite.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Callable

from geg.core import authz, write_auth
from geg.core.config import ElectionConfig
from geg.envelopes.types import (
    AggregateArtifact,
    BallotEnvelope,
    DecryptionShareEnvelope,
    DKGResultSubmission,
    ResultArtifact,
)
from geg.ports.data_layer import (
    ElectionDataLayer,
    ElectionFilter,
    ElectionRecord,
    FinalizedKey,
    ImmutabilityError,
    WriteAuthorizationError,
)


@dataclass
class _Stored:
    config: ElectionConfig
    cancelled: bool = False
    dkg_by_keyper: dict[int, DKGResultSubmission] = field(default_factory=dict)
    ballots: list[BallotEnvelope] = field(default_factory=list)
    aggregate_by_keyper: dict[int, AggregateArtifact] = field(default_factory=dict)
    shares_by_keyper: dict[int, DecryptionShareEnvelope] = field(default_factory=dict)
    result: ResultArtifact | None = None


class InMemoryDataLayer(ElectionDataLayer):
    def __init__(self, clock: Callable[[], int] | None = None):
        self._elections: dict[bytes, _Stored] = {}
        self._next_id = 0  # registry-style sequential election ids (1, 2, …)
        self._clock = clock or (lambda: 0)

    # -- helpers ------------------------------------------------------------ #

    def _get(self, election_id: bytes) -> _Stored:
        st = self._elections.get(election_id)
        if st is None:
            raise KeyError(f"unknown election {election_id.hex()}")
        return st

    def _keyper_index_by_recovery(self, config: ElectionConfig, digest: bytes, sig: bytes) -> int:
        """Recover the keyper from a content signature; return its 1-based index."""
        try:
            recovered = write_auth.recover_digest(digest, sig)
        except Exception as exc:  # noqa: BLE001
            raise WriteAuthorizationError("bad keyper signature") from exc
        for i, k in enumerate(config.keypers, start=1):
            if k.signing_key == recovered:
                return i
        raise WriteAuthorizationError("signature matches no registered keyper")

    # -- election lifecycle ------------------------------------------------- #

    def register_election(self, config: ElectionConfig, admin_sig: bytes) -> bytes:
        if not authz.verify_register(config.admin_key, admin_sig, config):
            raise WriteAuthorizationError("register: bad admin signature")
        self._next_id += 1
        election_id = self._next_id.to_bytes(32, "big")  # registry-style sequential id
        stored = replace(config, election_id=election_id)
        self._elections[election_id] = _Stored(config=stored)
        return election_id

    def cancel_election(self, election_id: bytes, admin_sig: bytes) -> None:
        st = self._get(election_id)
        if self._clock() >= st.config.voting_start:
            raise ImmutabilityError("Voting has already started; an election can only be cancelled before it opens.")
        if not authz.verify_request(st.config.admin_key, admin_sig, "cancel", election_id):
            raise WriteAuthorizationError("cancel: bad admin signature")
        st.cancelled = True

    def get_election(self, election_id: bytes) -> ElectionRecord:
        st = self._get(election_id)
        return ElectionRecord(
            config=st.config, cancelled=st.cancelled, finalized_key=self.get_finalized_key(election_id)
        )

    def list_elections(self, filter: ElectionFilter | None = None) -> list[bytes]:
        out = []
        for eid, st in self._elections.items():
            if filter and filter.admin_key is not None and st.config.admin_key != filter.admin_key:
                continue
            out.append(eid)
        return out

    # -- DKG ---------------------------------------------------------------- #

    def submit_dkg_result(self, election_id, pk_election, committee_pks, keyper_sig) -> None:
        st = self._get(election_id)
        committee = [bytes(p) for p in committee_pks]
        digest = write_auth.dkg_result_digest(election_id, bytes(pk_election), committee)
        idx = self._keyper_index_by_recovery(st.config, digest, keyper_sig)
        submission = DKGResultSubmission(
            election_id=election_id,
            pk_election=bytes(pk_election),
            committee_pks=tuple(bytes(p) for p in committee_pks),
            keyper_signature=keyper_sig,
        )
        existing = st.dkg_by_keyper.get(idx)
        if existing is not None:
            # Append-only per dealer: identical resend is a no-op; a different
            # submission from the same keyper is rejected.
            if (existing.pk_election, existing.committee_pks) != (
                submission.pk_election,
                submission.committee_pks,
            ):
                raise ImmutabilityError(f"keyper {idx} already submitted a different DKG result")
            return
        st.dkg_by_keyper[idx] = submission

    def get_dkg_submissions(self, election_id) -> list[DKGResultSubmission]:
        st = self._get(election_id)
        return [st.dkg_by_keyper[i] for i in sorted(st.dkg_by_keyper)]

    def get_finalized_key(self, election_id) -> FinalizedKey | None:
        st = self._get(election_id)
        needed = st.config.threshold.t + 1
        groups: dict[tuple, set[int]] = {}
        for idx, sub in st.dkg_by_keyper.items():
            key = (sub.pk_election, sub.committee_pks)
            groups.setdefault(key, set()).add(idx)
        for (pk, committee), keypers in groups.items():
            if len(keypers) >= needed:
                return FinalizedKey(pk_election=pk, committee_pks=committee)
        return None

    # -- ballots ------------------------------------------------------------ #

    def submit_ballot(self, election_id, ballot: BallotEnvelope) -> int:
        st = self._get(election_id)
        # Ballot writes are open in the reference (gateway restriction, where
        # required, is enforced at the transport tier). Ballots are self-verifying;
        # verification is authoritative at tally time.
        seq = len(st.ballots)
        st.ballots.append(ballot)
        return seq

    def list_ballots(self, election_id, start: int, count: int) -> list[BallotEnvelope]:
        st = self._get(election_id)
        return st.ballots[start : start + count]

    def count_ballots(self, election_id) -> int:
        return len(self._get(election_id).ballots)

    # -- tally artifacts ---------------------------------------------------- #

    def submit_aggregate(self, election_id, aggregate: AggregateArtifact, keyper_sig) -> None:
        st = self._get(election_id)
        digest = write_auth.aggregate_digest_of(election_id, aggregate)
        idx = self._keyper_index_by_recovery(st.config, digest, keyper_sig)
        existing = st.aggregate_by_keyper.get(idx)
        if existing is not None and existing == aggregate:
            return  # idempotent resend of this keyper's current submission
        # Mutable per keyper *until the quorum finalizes*: a keyper that submitted a
        # wrong/stale aggregate can override it so honest keypers can re-converge
        # (aggregation is a deterministic re-derivation — unlike the one-shot DKG
        # result, which is append-only). Once t+1 keypers agree the aggregate is
        # canonical and frozen.
        if self._aggregate_finalized(st):
            raise ImmutabilityError("aggregate already finalized (quorum reached)")
        st.aggregate_by_keyper[idx] = aggregate  # submit or override

    def _aggregate_groups(self, election_id, st) -> dict[bytes, tuple[AggregateArtifact, set[int]]]:
        groups: dict[bytes, tuple[AggregateArtifact, set[int]]] = {}
        for idx, agg in st.aggregate_by_keyper.items():
            key = write_auth.aggregate_digest_of(election_id, agg)
            _, keypers = groups.setdefault(key, (agg, set()))
            keypers.add(idx)
        return groups

    def _aggregate_finalized(self, st) -> bool:
        needed = st.config.threshold.t + 1
        return any(len(kps) >= needed for _, kps in self._aggregate_groups(st.config.election_id, st).values())

    def get_aggregate(self, election_id) -> AggregateArtifact | None:
        st = self._get(election_id)
        needed = st.config.threshold.t + 1
        for agg, keypers in self._aggregate_groups(election_id, st).values():
            if len(keypers) >= needed:
                return agg
        return None

    def submit_decryption_share(self, election_id, share: DecryptionShareEnvelope, keyper_sig) -> None:
        st = self._get(election_id)
        shares = [e.sigma for e in share.entries]
        proofs = [(int.from_bytes(e.proof[:32], "big"), int.from_bytes(e.proof[32:], "big")) for e in share.entries]
        digest = write_auth.decryption_share_digest(election_id, shares, proofs)
        idx = self._keyper_index_by_recovery(st.config, digest, keyper_sig)
        if idx != share.keyper_index:
            raise WriteAuthorizationError(
                f"share keyper_index {share.keyper_index} does not match signer {idx}"
            )
        existing = st.shares_by_keyper.get(idx)
        if existing is not None:
            # Idempotent on (election_id, keyper_index, candidate): identical
            # resend ok; different shares for the same key rejected.
            if existing != share:
                raise ImmutabilityError(f"keyper {idx} already submitted different shares")
            return
        st.shares_by_keyper[idx] = share

    def list_decryption_shares(self, election_id) -> list[DecryptionShareEnvelope]:
        st = self._get(election_id)
        return [st.shares_by_keyper[i] for i in sorted(st.shares_by_keyper)]

    def publish_result(self, election_id, result: ResultArtifact, result_publisher_sig) -> None:
        st = self._get(election_id)
        if not authz.verify_request(st.config.result_publisher_key, result_publisher_sig, "result", election_id):
            raise WriteAuthorizationError("publish_result: bad result-publisher signature")
        if st.result is not None:
            if st.result != result:
                raise ImmutabilityError("result already published (append-only)")
            return
        st.result = result

    def get_result(self, election_id) -> ResultArtifact | None:
        return self._get(election_id).result

    # -- capability --------------------------------------------------------- #

    def verifiability_tier(self) -> int:
        return 0
