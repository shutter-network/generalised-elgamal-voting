"""Reusable ``ElectionDataLayer`` conformance suite (DESIGN.md §5.1, §9).

``DataLayerConformance`` is a base class of behavioural tests for the port
contract — ordering, immutability, the finalization quorum rule, the authz
matrix, idempotent shares, and public reads. Every adapter subclasses it and
supplies a ``backend`` fixture; it is correct iff it passes these unmodified.

The suite is abstracted over **two seams** so the *same assertions* run against
backends with different authorization and time models (DESIGN.md §5.1: identity
interpretation is adapter-specific):

* **Authorization** — a write is issued through ``backend.dl(role)`` (the adapter
  authorized to act as ``role``) with ``backend.sig(role, op)`` (the credential to
  pass). Signature-checking backends (in-memory, database) return one adapter and
  real Schnorr request signatures; the chain backend returns a per-actor adapter
  bound to that role's Ethereum key and an empty sig.
* **Time** — ``backend.set_time(t)`` advances the backend's clock (a ``ManualClock``
  for memory/DB; an Anvil warp for chain).

Artifacts are well-formed but not crypto-valid — the data layer performs no proof
verification (availability only), so structural artifacts exercise the contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import pytest

from geg.core import write_auth
from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.envelopes.types import (
    AggregateArtifact,
    Attestation,
    BallotEnvelope,
    Ciphertext,
    DecryptionShareEntry,
    DecryptionShareEnvelope,
    ResultArtifact,
)
from geg.ports.data_layer import ImmutabilityError, WriteAuthorizationError

# Election ids are registry-assigned sequential values; a fresh backend per test
# means the first (and usually only) registration is id 1.
ELECTION_ID = (1).to_bytes(32, "big")
N, T = 3, 1
NUM_CANDIDATES, BUDGET = 3, 3


def _b(size: int, fill: int) -> bytes:
    return bytes([fill % 256]) * size


class ManualClock:
    def __init__(self, t: int = 0):
        self.t = t

    def __call__(self) -> int:
        return self.t

    def set(self, t: int) -> None:
        self.t = t


# --------------------------------------------------------------------------- #
#  Backend seam
# --------------------------------------------------------------------------- #

class ConformanceBackend(ABC):
    """The two-seam abstraction the conformance tests drive.

    ``config`` carries backend-appropriate identities. ``dl(role)`` returns the
    adapter authorized to write as ``role`` (``"admin"``, ``"aggregator"``,
    ``"gateway"``, ``"keyper1".."keyperN"``, ``"outsider"``); ``reader()`` is a
    public read handle. ``sig(role, op)`` is the credential to pass for that write.
    """

    config: ElectionConfig

    @abstractmethod
    def dl(self, role: str): ...

    @abstractmethod
    def reader(self): ...

    @abstractmethod
    def sig(self, role: str, op: str) -> bytes: ...

    @abstractmethod
    def set_time(self, t: int) -> None: ...

    # -- well-formed dummy artifacts (shared) ------------------------------- #

    def pk_and_committee(self, fill: int = 0xA0):
        return _b(96, fill), [_b(96, fill + 1 + i) for i in range(N)]

    def ballot(self, pseudonym: bytes = b"\x22" * 32) -> BallotEnvelope:
        att = Attestation(
            election_id=ELECTION_ID, pseudonym=pseudonym, vk=_b(48, 0x33),
            weight=1, signature=_b(80, 0x44),
        )
        return BallotEnvelope(
            election_id=ELECTION_ID, pseudonym=pseudonym, vk=_b(48, 0x33),
            ciphertexts=tuple(Ciphertext(c1=_b(96, 1), c2=_b(96, 2)) for _ in range(NUM_CANDIDATES)),
            zk_proof=b"\x01\x02\x03", voter_signature=_b(80, 0x55), attestation=att,
        )

    def aggregate(self, fill: int = 7) -> AggregateArtifact:
        return AggregateArtifact(
            election_id=ELECTION_ID,
            aggregates=tuple(Ciphertext(c1=_b(96, fill), c2=_b(96, fill + 1)) for _ in range(NUM_CANDIDATES)),
            admitted=(0, 1), exclusions=(), total_admitted_weight=2,
        )

    def share(self, keyper_index: int) -> DecryptionShareEnvelope:
        return DecryptionShareEnvelope(
            election_id=ELECTION_ID, keyper_index=keyper_index,
            entries=tuple(DecryptionShareEntry(sigma=_b(96, 9), proof=_b(64, 0x0A)) for _ in range(NUM_CANDIDATES)),
        )

    def result(self) -> ResultArtifact:
        return ResultArtifact(election_id=ELECTION_ID, totals=(1, 1, 1), keyper_indices=(1, 2), bsgs_bound=6)

    def register_sig(self, role: str) -> bytes:
        """Credential for a register call. Registration binds the config, not an id
        (assigned by the backend); signature backends override. Chain ignores it."""
        return self.sig(role, "register")

    def register(self) -> None:
        self.dl("admin").register_election(self.config, self.register_sig("admin"))


# --------------------------------------------------------------------------- #
#  Signature backend (in-memory + database): one adapter, Schnorr request sigs
# --------------------------------------------------------------------------- #

class SignatureBackend(ConformanceBackend):
    """Backend for signature-checking adapters. ``adapter`` uses ``clock``."""

    def __init__(self, adapter, clock: ManualClock):
        from geg.core.authz import Signer

        self._adapter = adapter
        self._clock = clock
        self._signers = {
            "admin": Signer.generate(),
            "aggregator": Signer.generate(),
            "gateway": Signer.generate(),
            "outsider": Signer.generate(),
        }
        for i in range(1, N + 1):
            self._signers[f"keyper{i}"] = Signer.generate()

        self.config = ElectionConfig(
            election_id=ELECTION_ID,
            num_candidates=NUM_CANDIDATES,
            budget=BUDGET,
            mode=Mode.EXACT,
            variant=Variant.A,
            weighted=True,
            max_weight=10,
            duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=1_000,
            voting_end=2_000,
            tally_deadline=3_000,
            threshold=Threshold(t=T, n=N),
            keypers=tuple(
                KeyperIdentity(signing_key=self._signers[f"keyper{i}"].identity, endpoint=f"http://k{i}")
                for i in range(1, N + 1)
            ),
            eligibility_key=_b(48, 0xE1),
            aggregator_key=self._signers["aggregator"].identity,
            gateway_keys=(self._signers["gateway"].identity,),
            admin_key=self._signers["admin"].identity,
            protocol_version="SHUTTER-VOTE-v1",
        )

    def dl(self, role: str):
        return self._adapter

    def reader(self):
        return self._adapter

    def sig(self, role: str, op: str) -> bytes:
        return self._signers[role].sign(op, ELECTION_ID)

    def register_sig(self, role: str) -> bytes:
        return self._signers[role].sign_register(self.config)

    def dkg_sig(self, role: str, pk: bytes, committee: list[bytes]) -> bytes:
        return write_auth.sign_dkg_result(self._signers[role].private_key, ELECTION_ID, pk, committee)

    def share_sig(self, role: str, share) -> bytes:
        sigmas = [e.sigma for e in share.entries]
        proofs = [(int.from_bytes(e.proof[:32], "big"), int.from_bytes(e.proof[32:], "big")) for e in share.entries]
        return write_auth.sign_decryption_share(self._signers[role].private_key, ELECTION_ID, sigmas, proofs)

    def aggregate_sig(self, role: str, aggregate) -> bytes:
        return write_auth.sign_aggregate(self._signers[role].private_key, ELECTION_ID, aggregate)

    def set_time(self, t: int) -> None:
        self._clock.set(t)


# --------------------------------------------------------------------------- #
#  Conformance behaviours
# --------------------------------------------------------------------------- #

class DataLayerConformance:
    """Behavioural conformance tests. Subclasses provide the ``backend`` fixture."""

    # -- lifecycle + authz -------------------------------------------------- #

    def test_register_and_get_round_trip(self, backend):
        backend.register()
        rec = backend.reader().get_election(ELECTION_ID)
        assert rec.config.election_id == ELECTION_ID
        assert rec.cancelled is False
        assert rec.finalized_key is None

    def test_register_rejects_unauthorized_writer(self, backend):
        with pytest.raises(WriteAuthorizationError):
            backend.dl("aggregator").register_election(backend.config, backend.register_sig("aggregator"))

    def test_register_assigns_sequential_ids(self, backend):
        # Ids are backend-assigned (registry-style), so each call yields a new id.
        eid1 = backend.dl("admin").register_election(backend.config, backend.register_sig("admin"))
        eid2 = backend.dl("admin").register_election(backend.config, backend.register_sig("admin"))
        assert eid1 == (1).to_bytes(32, "big")
        assert eid2 == (2).to_bytes(32, "big")

    def test_list_elections_and_filter(self, backend):
        from geg.ports.data_layer import ElectionFilter

        backend.register()
        assert ELECTION_ID in backend.reader().list_elections()
        assert backend.reader().list_elections(ElectionFilter(admin_key=backend.config.admin_key)) == [ELECTION_ID]
        assert backend.reader().list_elections(ElectionFilter(admin_key=b"\x00" * len(backend.config.admin_key))) == []

    def test_cancel_before_start_ok(self, backend):
        backend.register()
        backend.set_time(500)
        backend.dl("admin").cancel_election(ELECTION_ID, backend.sig("admin", "cancel"))
        assert backend.reader().get_election(ELECTION_ID).cancelled is True

    def test_cancel_after_start_rejected(self, backend):
        backend.register()
        backend.set_time(1_000)
        with pytest.raises(ImmutabilityError):
            backend.dl("admin").cancel_election(ELECTION_ID, backend.sig("admin", "cancel"))

    def test_cancel_unauthorized_rejected(self, backend):
        backend.register()
        backend.set_time(500)
        with pytest.raises(WriteAuthorizationError):
            backend.dl("aggregator").cancel_election(ELECTION_ID, backend.sig("aggregator", "cancel"))

    # -- ballots: ordering, sequence, pagination --------------------------- #

    def test_ballot_ordering_and_monotonic_sequence(self, backend):
        backend.register()
        seqs = [backend.dl("gateway").submit_ballot(ELECTION_ID, backend.ballot(bytes([i]) * 32)) for i in range(5)]
        assert seqs == [0, 1, 2, 3, 4]
        assert backend.reader().count_ballots(ELECTION_ID) == 5
        listed = backend.reader().list_ballots(ELECTION_ID, 0, 5)
        assert [b.pseudonym for b in listed] == [bytes([i]) * 32 for i in range(5)]

    def test_ballot_pagination(self, backend):
        backend.register()
        for i in range(5):
            backend.dl("gateway").submit_ballot(ELECTION_ID, backend.ballot(bytes([i]) * 32))
        page = backend.reader().list_ballots(ELECTION_ID, 2, 2)
        assert [b.pseudonym for b in page] == [bytes([2]) * 32, bytes([3]) * 32]

    # -- DKG finalization quorum rule -------------------------------------- #

    def test_dkg_finalizes_at_quorum(self, backend):
        backend.register()
        pk, committee = backend.pk_and_committee()
        backend.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("keyper1", pk, committee))
        assert backend.reader().get_finalized_key(ELECTION_ID) is None  # 1 < t+1
        backend.dl("keyper2").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("keyper2", pk, committee))
        fk = backend.reader().get_finalized_key(ELECTION_ID)
        assert fk is not None and fk.pk_election == pk

    def test_dkg_divergent_submissions_do_not_finalize(self, backend):
        backend.register()
        pk_a, com_a = backend.pk_and_committee(0xA0)
        pk_b, com_b = backend.pk_and_committee(0xB0)
        backend.dl("keyper1").submit_dkg_result(ELECTION_ID, pk_a, com_a, backend.dkg_sig("keyper1", pk_a, com_a))
        backend.dl("keyper2").submit_dkg_result(ELECTION_ID, pk_b, com_b, backend.dkg_sig("keyper2", pk_b, com_b))
        assert backend.reader().get_finalized_key(ELECTION_ID) is None

    def test_dkg_non_keyper_rejected(self, backend):
        backend.register()
        pk, committee = backend.pk_and_committee()
        with pytest.raises(WriteAuthorizationError):
            backend.dl("outsider").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("outsider", pk, committee))

    def test_dkg_append_only_per_dealer(self, backend):
        backend.register()
        pk, committee = backend.pk_and_committee()
        backend.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("keyper1", pk, committee))
        # Identical resend: no-op.
        backend.dl("keyper1").submit_dkg_result(ELECTION_ID, pk, committee, backend.dkg_sig("keyper1", pk, committee))
        # Different submission from same dealer: rejected.
        pk2, com2 = backend.pk_and_committee(0xC0)
        with pytest.raises(ImmutabilityError):
            backend.dl("keyper1").submit_dkg_result(ELECTION_ID, pk2, com2, backend.dkg_sig("keyper1", pk2, com2))
        assert len(backend.reader().get_dkg_submissions(ELECTION_ID)) == 1

    # -- decryption shares: authz + idempotency ---------------------------- #

    def test_share_submit_and_idempotent_resend(self, backend):
        backend.register()
        share = backend.share(1)
        backend.dl("keyper1").submit_decryption_share(ELECTION_ID, share, backend.share_sig("keyper1", share))
        backend.dl("keyper1").submit_decryption_share(ELECTION_ID, share, backend.share_sig("keyper1", share))
        assert len(backend.reader().list_decryption_shares(ELECTION_ID)) == 1

    def test_share_non_keyper_rejected(self, backend):
        backend.register()
        share = backend.share(1)
        with pytest.raises(WriteAuthorizationError):
            backend.dl("aggregator").submit_decryption_share(ELECTION_ID, share, backend.share_sig("aggregator", share))

    def test_share_keyper_index_must_match_signer(self, backend):
        backend.register()
        share = backend.share(1)  # claims keyper_index 1
        with pytest.raises(WriteAuthorizationError):
            # signed by keyper 2 but the envelope claims keyper_index 1
            backend.dl("keyper2").submit_decryption_share(ELECTION_ID, share, backend.share_sig("keyper2", share))

    # -- aggregate + result ------------------------------------------------- #

    def test_aggregate_none_before_publish(self, backend):
        backend.register()
        assert backend.reader().get_aggregate(ELECTION_ID) is None

    def test_aggregate_quorum_authz_and_idempotent(self, backend):
        backend.register()
        agg = backend.aggregate()

        # Non-keyper (aggregator) cannot submit the aggregate — it is a keyper write now.
        with pytest.raises(WriteAuthorizationError):
            backend.dl("aggregator").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("aggregator", agg))

        # One keyper is not a quorum (t+1 = 2): not yet canonical.
        backend.dl("keyper1").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper1", agg))
        assert backend.reader().get_aggregate(ELECTION_ID) is None
        # Identical resend by the same keyper: no-op.
        backend.dl("keyper1").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper1", agg))
        assert backend.reader().get_aggregate(ELECTION_ID) is None

        # A byte-identical submission from a second keyper reaches the quorum → canonical.
        backend.dl("keyper2").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper2", agg))
        assert backend.reader().get_aggregate(ELECTION_ID) == agg

    def test_aggregate_keyper_can_override_until_finalized(self, backend):
        backend.register()
        agg = backend.aggregate()
        other = backend.aggregate(fill=0x50)
        assert agg != other
        # A keyper may correct a wrong/stale submission while the aggregate is not yet
        # canonical (deterministic re-derivation → honest keypers re-converge).
        backend.dl("keyper1").submit_aggregate(ELECTION_ID, other, backend.aggregate_sig("keyper1", other))
        backend.dl("keyper1").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper1", agg))  # override
        assert backend.reader().get_aggregate(ELECTION_ID) is None  # still 1 vote for agg
        # keyper2 agrees with keyper1's (overridden) aggregate → quorum → canonical.
        backend.dl("keyper2").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper2", agg))
        assert backend.reader().get_aggregate(ELECTION_ID) == agg
        # Once finalized, further submissions (even overrides) are frozen out.
        with pytest.raises(ImmutabilityError):
            backend.dl("keyper3").submit_aggregate(ELECTION_ID, other, backend.aggregate_sig("keyper3", other))

    def test_aggregate_divergent_submissions_do_not_finalize(self, backend):
        backend.register()
        agg = backend.aggregate()
        other = backend.aggregate(fill=0x50)
        # Two keypers disagree → neither artifact has a t+1 quorum.
        backend.dl("keyper1").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper1", agg))
        backend.dl("keyper2").submit_aggregate(ELECTION_ID, other, backend.aggregate_sig("keyper2", other))
        assert backend.reader().get_aggregate(ELECTION_ID) is None
        # keyper2 overrides to agree with keyper1 → quorum on that artifact.
        backend.dl("keyper2").submit_aggregate(ELECTION_ID, agg, backend.aggregate_sig("keyper2", agg))
        assert backend.reader().get_aggregate(ELECTION_ID) == agg

    def test_result_publish_authz_and_read(self, backend):
        backend.register()
        assert backend.reader().get_result(ELECTION_ID) is None
        with pytest.raises(WriteAuthorizationError):
            backend.dl("admin").publish_result(ELECTION_ID, backend.result(), backend.sig("admin", "result"))
        backend.dl("aggregator").publish_result(ELECTION_ID, backend.result(), backend.sig("aggregator", "result"))
        assert backend.reader().get_result(ELECTION_ID) == backend.result()

    # -- capability --------------------------------------------------------- #

    def test_verifiability_tier_is_zero(self, backend):
        assert backend.reader().verifiability_tier() == 0
