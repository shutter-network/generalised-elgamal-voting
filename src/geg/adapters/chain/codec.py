"""Conversions between geg envelopes and the on-chain contract structs.

Enum-like fields are ``uint8`` on chain; the attestation (with weight) is packed
verbatim into the ballot's ``wrAttestation`` bytes (the contract does not
interpret it). ``election_id`` is a ``bytes32`` off chain and the ``uint256``
contract ``electionId`` on chain.
"""

from __future__ import annotations

import json

from geg.core.config import DuplicatePolicy, Mode, Variant
from geg.envelopes import codecs
from geg.envelopes.types import (
    AggregateArtifact,
    BallotEnvelope,
    Ciphertext,
    DecryptionShareEntry,
    DecryptionShareEnvelope,
    Exclusion,
    ExclusionReason,
    StoredBallot,
)

MODE_TO_U8 = {Mode.EXACT: 0, Mode.AT_MOST: 1}
U8_TO_MODE = {v: k for k, v in MODE_TO_U8.items()}
VARIANT_TO_U8 = {Variant.A: 0, Variant.B: 1}
U8_TO_VARIANT = {v: k for k, v in VARIANT_TO_U8.items()}
DUP_TO_U8 = {DuplicatePolicy.FIRST_WINS: 0, DuplicatePolicy.LAST_WINS: 1}
U8_TO_DUP = {v: k for k, v in DUP_TO_U8.items()}
REASON_TO_U8 = {
    ExclusionReason.INVALID_PROOF: 0,
    ExclusionReason.INVALID_SIGNATURE: 1,
    ExclusionReason.INVALID_ATTESTATION: 2,
    ExclusionReason.DUPLICATE_PSEUDONYM: 3,
    ExclusionReason.MALFORMED: 4,
    ExclusionReason.OUT_OF_WINDOW: 5,
}
U8_TO_REASON = {v: k for k, v in REASON_TO_U8.items()}


def eid_to_uint(election_id: bytes) -> int:
    return int.from_bytes(election_id, "big")


def uint_to_eid(value: int) -> bytes:
    return int(value).to_bytes(32, "big")


# --- attestation packing (into wrAttestation bytes) ------------------------ #

def pack_attestation(att) -> bytes:
    return json.dumps(codecs.enc_attestation(att), separators=(",", ":")).encode("utf-8")


def unpack_attestation(raw: bytes):
    return codecs.dec_attestation(json.loads(bytes(raw).decode("utf-8")))


# --- ballot ---------------------------------------------------------------- #

def ballot_to_tuple(env: BallotEnvelope):
    """Contract ``Ballot``: (pseudonym, vk, ciphertexts[(c1,c2)], zkProof, voterSignature, wrAttestation)."""
    cts = [(ct.c1, ct.c2) for ct in env.ciphertexts]
    return (env.pseudonym, env.vk, cts, env.zk_proof, env.voter_signature, pack_attestation(env.attestation))


def ballot_record_from_contract(raw, election_id: bytes, sequence_number: int) -> StoredBallot:
    """Contract ``BallotRecord``: (ballot, submittedAt, submittedBy) -> StoredBallot.

    ``submittedAt`` is the block timestamp the contract stamped at accept time — the
    one adversarially authoritative receive time in the system, since the chain is the
    only backend whose clock the data-layer operator does not control.
    """
    ballot, submitted_at = raw[0], raw[1]
    return StoredBallot(
        sequence_number=sequence_number,
        envelope=ballot_from_contract(ballot, election_id),
        submitted_at=int(submitted_at),
    )


def ballot_from_contract(raw, election_id: bytes) -> BallotEnvelope:
    pseudonym, vk, cts, zk_proof, voter_sig, wr = raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]
    return BallotEnvelope(
        election_id=election_id,
        pseudonym=bytes(pseudonym),
        vk=bytes(vk),
        ciphertexts=tuple(Ciphertext(c1=bytes(c[0]), c2=bytes(c[1])) for c in cts),
        zk_proof=bytes(zk_proof),
        voter_signature=bytes(voter_sig),
        attestation=unpack_attestation(wr),
    )


# --- aggregate ------------------------------------------------------------- #

def aggregate_to_tuple(agg: AggregateArtifact):
    """Contract ``EncryptedTally``: (aggregates[(c1,c2)], admitted[], exclusions[(seq,reason)], totalAdmittedWeight)."""
    aggregates = [(ct.c1, ct.c2) for ct in agg.aggregates]
    admitted = [int(s) for s in agg.admitted]
    exclusions = [(int(x.sequence_number), REASON_TO_U8[x.reason]) for x in agg.exclusions]
    return (aggregates, admitted, exclusions, int(agg.total_admitted_weight))


def aggregate_from_contract(raw, election_id: bytes) -> AggregateArtifact:
    aggregates, admitted, exclusions, total_weight = raw[0], raw[1], raw[2], raw[3]
    return AggregateArtifact(
        election_id=election_id,
        aggregates=tuple(Ciphertext(c1=bytes(c[0]), c2=bytes(c[1])) for c in aggregates),
        admitted=tuple(int(s) for s in admitted),
        exclusions=tuple(Exclusion(sequence_number=int(x[0]), reason=U8_TO_REASON[int(x[1])]) for x in exclusions),
        total_admitted_weight=int(total_weight),
    )


# --- decryption share ------------------------------------------------------ #

def share_to_contract(share: DecryptionShareEnvelope):
    """Return (shares[bytes], proofs[(e,z)]) for ``submitDecryptionShare``."""
    shares = [entry.sigma for entry in share.entries]
    proofs = [
        (int.from_bytes(entry.proof[:32], "big"), int.from_bytes(entry.proof[32:], "big"))
        for entry in share.entries
    ]
    return shares, proofs


def share_from_contract(raw, election_id: bytes) -> DecryptionShareEnvelope:
    """Contract ``DecryptionShare``: (keyperIndex u8 [0-based], submittedAt, shares[], proofs[(e,z)])."""
    keyper_index_0based, _submitted_at, shares, proofs = raw[0], raw[1], raw[2], raw[3]
    entries = []
    for sigma, proof in zip(shares, proofs):
        e_val, z_val = int(proof[0]), int(proof[1])
        entries.append(
            DecryptionShareEntry(sigma=bytes(sigma), proof=e_val.to_bytes(32, "big") + z_val.to_bytes(32, "big"))
        )
    return DecryptionShareEnvelope(
        election_id=election_id, keyper_index=int(keyper_index_0based) + 1, entries=tuple(entries)
    )
