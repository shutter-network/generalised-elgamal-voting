"""Shared test fixtures: a full election crypto setup + ballot/share factories.

Provides an ``env`` fixture that runs a real DKG, holds the eligibility keypair,
and can mint valid ballot envelopes (V1 or legacy attestation) and keyper
decryption-share envelopes for an aggregate. Reused by the admission, aggregation,
adapter, and service tests so they exercise real crypto end-to-end.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from geg.core.config import DuplicatePolicy, ElectionConfig, KeyperIdentity, Mode, Threshold, Variant
from geg.crypto import attestation as att_crypto
from geg.crypto import ballot as ballot_crypto
from geg.crypto import proofs, schnorr
from geg.crypto.dkg import KeyperDKGState, derive_joint_mpk, derive_mpk_share
from geg.crypto.points import g1_to_compressed, g2_from_compressed, g2_to_compressed
from geg.envelopes.types import (
    Attestation,
    AttestationScheme,
    BallotEnvelope,
    Ciphertext,
    DecryptionShareEntry,
    DecryptionShareEnvelope,
)

# Election ids are registry-assigned sequential values; a fresh data layer per test
# means the first registration is id 1.
ELECTION_ID = (1).to_bytes(32, "big")


def _run_dkg(n: int, t: int):
    states = {i: KeyperDKGState() for i in range(1, n + 1)}
    comms, shares = {}, {}
    for i, st in states.items():
        c, s = st.round1(i, n, t)
        comms[i], shares[i] = c, s
    for i, st in states.items():
        st.round2(comms, {d: shares[d][i] for d in states})
    mpk = derive_joint_mpk(comms)
    committee = {i: derive_mpk_share(i, comms) for i in states}
    return mpk, committee, states


@dataclass
class Env:
    mpk_bytes: bytes
    committee_pks: tuple  # bytes, index keyper_index-1
    keyper_states: dict
    elig_sk: int
    elig_vk_bytes: bytes
    threshold_t: int
    n: int

    @property
    def mpk_point(self):
        return g2_from_compressed(self.mpk_bytes)

    def config(self, **overrides) -> ElectionConfig:
        base = dict(
            election_id=ELECTION_ID,
            num_candidates=3,
            budget=3,
            mode=Mode.EXACT,
            variant=Variant.A,
            weighted=True,
            max_weight=10,
            duplicate_policy=DuplicatePolicy.LAST_WINS,
            voting_start=1_000,
            voting_end=2_000,
            tally_deadline=3_000,
            threshold=Threshold(t=self.threshold_t, n=self.n),
            keypers=tuple(
                KeyperIdentity(signing_key=bytes([i]) * 20, url=f"http://k{i}") for i in range(self.n)
            ),
            eligibility_key=self.elig_vk_bytes,
            result_publisher_key=b"\xa1" * 20,
            gateway_keys=(b"\x91" * 20,),
            admin_key=b"\xad" * 20,
            protocol_version="SHUTTER-VOTE-v1",
        )
        base.update(overrides)
        return ElectionConfig(**base)

    def ballot(self, votes, pseudonym: bytes, *, weight: int = 1,
               scheme: AttestationScheme = AttestationScheme.V1,
               election_id: bytes = ELECTION_ID, budget: int = 3) -> BallotEnvelope:
        sk, vk = schnorr.keygen()
        vk_bytes = g1_to_compressed(vk)
        built = ballot_crypto.build_ballot(
            mpk=self.mpk_point, election_id=election_id, pseudonym=pseudonym,
            sk=sk, vk=vk, votes=votes, num_candidates=len(votes), budget=budget,
        )
        _, elig_vk_pt = schnorr.keygen(self.elig_sk)
        if scheme is AttestationScheme.V1:
            sig = att_crypto.sign_attestation(
                self.elig_sk, elig_vk_pt, election_id, pseudonym, vk_bytes, weight
            )
        else:
            weight = 1
            sig = att_crypto.sign_attestation_legacy(
                self.elig_sk, elig_vk_pt, election_id, pseudonym, vk_bytes
            )
        att = Attestation(
            election_id=election_id, pseudonym=pseudonym, vk=vk_bytes,
            weight=weight, signature=sig, scheme=scheme,
        )
        return BallotEnvelope(
            election_id=election_id, pseudonym=pseudonym, vk=vk_bytes,
            ciphertexts=tuple(Ciphertext(c1=a, c2=b) for (a, b) in built.ciphertexts),
            zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att,
        )

    def shares_for(self, aggregate, keyper_indices) -> list[DecryptionShareEnvelope]:
        """Produce DLEQ-proved decryption shares for an aggregate artifact."""
        out = []
        for i in keyper_indices:
            st = self.keyper_states[i]
            mpk_k = g2_from_compressed(self.committee_pks[i - 1])
            entries = []
            for j, ct in enumerate(aggregate.aggregates):
                c1 = g2_from_compressed(ct.c1)
                c2 = g2_from_compressed(ct.c2)
                sigma = st.partial_decrypt(c1)
                t = proofs.make_decrypt_transcript(aggregate.election_id, j)
                e, z = proofs.prove_decryption_share(t, c1, c2, mpk_k, sigma, st.combined_share, i)
                entries.append(
                    DecryptionShareEntry(sigma=g2_to_compressed(sigma), proof=proofs.encode_dleq(e, z))
                )
            out.append(DecryptionShareEnvelope(election_id=aggregate.election_id, keyper_index=i, entries=tuple(entries)))
        return out


@pytest.fixture
def env() -> Env:
    n, t = 3, 1
    mpk, committee, states = _run_dkg(n, t)
    elig_sk, elig_vk = schnorr.keygen()
    return Env(
        mpk_bytes=g2_to_compressed(mpk),
        committee_pks=tuple(g2_to_compressed(committee[i]) for i in range(1, n + 1)),
        keyper_states=states,
        elig_sk=elig_sk,
        elig_vk_bytes=g1_to_compressed(elig_vk),
        threshold_t=t,
        n=n,
    )


# --------------------------------------------------------------------------- #
#  Full service-wired environment (data layer + signers + keyper services)
# --------------------------------------------------------------------------- #

class ManualClock:
    def __init__(self, t: int = 0):
        self.t = t

    def __call__(self) -> int:
        return self.t

    def set(self, t: int) -> None:
        self.t = t


@dataclass
class FullEnv:
    clock: ManualClock
    dl: object
    admin: object  # authz.Signer
    result_publisher: object
    gateway: object
    keyper_signers: list
    elig: object  # StubEligibilityService
    keypers: list  # KeyperService
    config: ElectionConfig
    n: int
    t: int

    def voter_ballot(self, votes, pseudonym: bytes, *, weight: int = 1) -> BallotEnvelope:
        from geg.crypto import ballot as ballot_crypto
        from geg.ports.eligibility import AttestationRequest

        fk = self.dl.get_finalized_key(self.config.election_id)
        mpk = g2_from_compressed(fk.pk_election)
        sk, vk = schnorr.keygen()
        vk_bytes = g1_to_compressed(vk)
        built = ballot_crypto.build_ballot(
            mpk=mpk, election_id=self.config.election_id, pseudonym=pseudonym,
            sk=sk, vk=vk, votes=votes, num_candidates=self.config.num_candidates, budget=self.config.budget,
        )
        att = self.elig.issue_attestation(
            AttestationRequest(self.config.election_id, pseudonym, vk_bytes, weight)
        )
        return BallotEnvelope(
            election_id=self.config.election_id, pseudonym=pseudonym, vk=vk_bytes,
            ciphertexts=tuple(Ciphertext(c1=a, c2=b) for (a, b) in built.ciphertexts),
            zk_proof=built.zk_proof, voter_signature=built.voter_signature, attestation=att,
        )


def build_full_env(dl, clock) -> FullEnv:
    """Wire signers, config, eligibility, and keyper services onto a data layer."""
    from geg.adapters.eligibility_stub import StubEligibilityService
    from geg.core.authz import Signer
    from geg.services.keyper import KeyperService

    n, t = 3, 1
    admin = Signer.generate()
    result_publisher = Signer.generate()
    gateway = Signer.generate()
    keyper_signers = [Signer.generate() for _ in range(n)]
    elig_sk, _ = schnorr.keygen()
    elig = StubEligibilityService(elig_sk)

    config = ElectionConfig(
        election_id=ELECTION_ID,
        num_candidates=3,
        budget=3,
        mode=Mode.EXACT,
        variant=Variant.A,
        weighted=True,
        max_weight=10,
        duplicate_policy=DuplicatePolicy.LAST_WINS,
        voting_start=1_000,
        voting_end=2_000,
        tally_deadline=3_000,
        threshold=Threshold(t=t, n=n),
        keypers=tuple(
            KeyperIdentity(signing_key=keyper_signers[i].identity, url=f"http://k{i}") for i in range(n)
        ),
        eligibility_key=elig.eligibility_key,
        result_publisher_key=result_publisher.identity,
        gateway_keys=(gateway.identity,),
        admin_key=admin.identity,
        protocol_version="SHUTTER-VOTE-v1",
    )
    keypers = [KeyperService(i, keyper_signers[i - 1], dl, clock=clock) for i in range(1, n + 1)]
    return FullEnv(
        clock=clock, dl=dl, admin=admin, result_publisher=result_publisher, gateway=gateway,
        keyper_signers=keyper_signers, elig=elig, keypers=keypers, config=config, n=n, t=t,
    )


@pytest.fixture
def full_env() -> FullEnv:
    from geg.adapters.memory import InMemoryDataLayer

    clock = ManualClock(0)
    return build_full_env(InMemoryDataLayer(clock=clock), clock)
