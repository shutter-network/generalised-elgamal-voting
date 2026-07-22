"""Artifact envelope dataclasses (DESIGN.md §7.2).

In-memory representations of the five transport artifacts plus the
``ATTESTATION_V1`` credential. These are pure data holders; JSON
encoding/decoding and byte-length validation live in
:mod:`geg.envelopes.codecs`.

Byte fields are held as raw ``bytes`` here and only become ``0x``-hex at the JSON
boundary. Fixed byte sizes (from the SDK v1 codecs, DESIGN.md §7.2) are recorded
in :data:`SIZES` and enforced by the codecs so malformed input is rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# Fixed byte sizes of the crypto suite (DESIGN.md §7.1/§7.2). Enforced on decode.
G1_BYTES = 48  # compressed G1 (voter vk, Schnorr R, attestation/eligibility keys)
G2_BYTES = 96  # compressed G2 (ElGamal ciphertext components, sigma, committee PKs)
SCHNORR_BYTES = 80  # R (48) || s (32)
DLEQ_BYTES = 64  # e (32) || z (32)
BYTES32 = 32  # election_id, pseudonym

SIZES = {
    "g1": G1_BYTES,
    "g2": G2_BYTES,
    "schnorr": SCHNORR_BYTES,
    "dleq": DLEQ_BYTES,
    "bytes32": BYTES32,
}


class ExclusionReason(str, Enum):
    """Typed reasons a stored ballot was excluded from the aggregate (DESIGN.md §7.2)."""

    INVALID_PROOF = "INVALID_PROOF"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    INVALID_ATTESTATION = "INVALID_ATTESTATION"
    DUPLICATE_PSEUDONYM = "DUPLICATE_PSEUDONYM"
    MALFORMED = "MALFORMED"
    OUT_OF_WINDOW = "OUT_OF_WINDOW"


class AttestationScheme(str, Enum):
    """Which eligibility-credential scheme an attestation uses (DESIGN.md §5.2).

    ``V1`` is the weighted, domain-separated ``ATTESTATION_V1``. ``LEGACY`` is the
    weightless Wahlregister scheme (``keccak(electionId‖pseudonym‖vk)``), carried
    for interop with existing Munich-style deployments and only valid at weight 1.
    """

    V1 = "ATTESTATION_V1"
    LEGACY = "ATTESTATION_LEGACY"


@dataclass(frozen=True)
class Ciphertext:
    """Exponential-ElGamal ciphertext in G2: ``(C1, C2)`` (DESIGN.md §7.1)."""

    c1: bytes  # G2, 96 bytes
    c2: bytes  # G2, 96 bytes


@dataclass(frozen=True)
class Attestation:
    """``ATTESTATION_V1`` eligibility credential (DESIGN.md §5.2, §7.1).

    A Schnorr-on-G1 signature by ``eligibility_key`` over a domain-separated
    transcript of ``(election_id, pseudonym, vk, weight)``. Extends the prior
    Wahlregister attestation (which covered the tuple without ``weight``) and is a
    distinct codec, not a silent modification. ``weight`` travels inside the
    credential so the whole tally is re-derivable from public artifacts.
    """

    election_id: bytes  # bytes32
    pseudonym: bytes  # bytes32
    vk: bytes  # G1, 48 bytes — voter ephemeral Schnorr verification key
    weight: int  # 1 <= weight <= max_weight (must be 1 for the LEGACY scheme)
    signature: bytes  # Schnorr, 80 bytes, by eligibility_key over the tuple
    scheme: AttestationScheme = AttestationScheme.V1


@dataclass(frozen=True)
class BallotEnvelope:
    """Ballot artifact (DESIGN.md §7.2).

    Generalises the on-chain ballot (``eth_client.py::_decode_ballot``) by adding
    an explicit ``election_id`` and carrying the eligibility credential as
    ``attestation`` (``ATTESTATION_V1``, which carries ``weight``) rather than the
    weightless ``wrAttestation``.
    """

    election_id: bytes  # bytes32
    pseudonym: bytes  # bytes32
    vk: bytes  # G1, 48 bytes
    ciphertexts: tuple[Ciphertext, ...]  # one per candidate
    zk_proof: bytes  # versioned BallotValidityProof encoding (variable length)
    voter_signature: bytes  # Schnorr, 80 bytes, over canonical ballot message
    attestation: Attestation


@dataclass(frozen=True)
class DKGResultSubmission:
    """A keyper's signed DKG result vote (DESIGN.md §7.2).

    The finalized key exists iff >= t+1 registered keypers submit byte-identical
    ``(pk_election, committee_pks)`` — the finalization quorum rule (DESIGN.md
    §5.1). This envelope is one such submission.
    """

    election_id: bytes  # bytes32
    pk_election: bytes  # G2, 96 bytes — joint election public key
    committee_pks: tuple[bytes, ...]  # each G2, 96 bytes — per-keyper public shares
    keyper_signature: bytes  # signature by the submitting keyper's registered key


@dataclass(frozen=True)
class DecryptionShareEntry:
    """One candidate's partial decryption: ``sigma`` plus its DLEQ proof."""

    sigma: bytes  # G2, 96 bytes — sigma_k = msk_k * C1
    proof: bytes  # DLEQ, 64 bytes (e || z)


@dataclass(frozen=True)
class DecryptionShareEnvelope:
    """A keyper's per-candidate decryption shares (DESIGN.md §7.2, §8.2)."""

    election_id: bytes  # bytes32
    keyper_index: int
    entries: tuple[DecryptionShareEntry, ...]  # one per candidate


@dataclass(frozen=True)
class Exclusion:
    """A ballot excluded from the aggregate, with a typed reason (DESIGN.md §7.2)."""

    sequence_number: int
    reason: ExclusionReason


@dataclass(frozen=True)
class AggregateArtifact:
    """Aggregate artifact with its admitted set (DESIGN.md §7.2, §8.1).

    Publishing the admitted set (plus per-exclusion reason codes and the total
    admitted weight) makes the aggregator's admission decisions public and
    re-checkable, and enables the keyper hardening profile (DESIGN.md §8.2). This
    has no equivalent on today's contract — it is a new artifact.
    """

    election_id: bytes  # bytes32
    aggregates: tuple[Ciphertext, ...]  # per-candidate homomorphic sum
    admitted: tuple[int, ...]  # sequence numbers included in the aggregate
    exclusions: tuple[Exclusion, ...]  # (sequence_number, reason) per excluded ballot
    total_admitted_weight: int


@dataclass(frozen=True)
class ResultArtifact:
    """Final result artifact (DESIGN.md §7.2, §8.3)."""

    election_id: bytes  # bytes32
    totals: tuple[int, ...]  # per-candidate plaintext totals
    keyper_indices: tuple[int, ...]  # the t+1 keyper indices whose shares were used
    bsgs_bound: int  # derived bound = budget * sum(admitted weights)
