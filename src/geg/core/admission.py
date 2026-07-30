"""Ballot admission — the correctness kernel.

A deterministic function from the data layer's ordered ballot list + election
config + eligibility key to an **admitted set** and typed **exclusion reasons**.
This is the authoritative definition of which ballots the tally counts; each keyper
runs it to produce its aggregate submission, the auditor runs it to re-derive the
tally, and it is reproducible by anyone from public data alone.

Verification is authoritative here (at tally time), not at the gateway. Each
ballot is validated independently; then the duplicate policy is applied over the
still-valid ballots in the data layer's stable total order.

Reason precedence per ballot (first failure wins): ``MALFORMED`` (wrong-election
binding / structural) → ``OUT_OF_WINDOW`` → ``INVALID_ATTESTATION`` →
``INVALID_SIGNATURE`` / ``INVALID_PROOF``. ``DUPLICATE_PSEUDONYM`` is assigned
only among otherwise-valid ballots.
"""

from __future__ import annotations

from dataclasses import dataclass

from geg.core.config import DuplicatePolicy, ElectionConfig
from geg.crypto.ballot import verify_ballot_crypto
from geg.crypto.points import g2_from_compressed
from geg.envelopes.types import BallotEnvelope, Exclusion, ExclusionReason
from geg.ports.eligibility import verify_attestation
from geg.core.state import is_voting_open


@dataclass(frozen=True)
class StoredBallot:
    """A ballot as the data layer stores it: an envelope with a stable sequence.

    ``submitted_at`` is the adapter's authoritative receive time where it has one
    (block time / NTP-disciplined service clock); ``None`` when the adapter has no
    authoritative time and enforces the window at write instead,
    in which case the ``OUT_OF_WINDOW`` check is skipped here.
    """

    sequence_number: int
    envelope: BallotEnvelope
    submitted_at: int | None = None


@dataclass(frozen=True)
class AdmittedBallot:
    sequence_number: int
    envelope: BallotEnvelope
    weight: int


@dataclass(frozen=True)
class AdmissionResult:
    admitted: tuple[AdmittedBallot, ...]
    exclusions: tuple[Exclusion, ...]
    total_admitted_weight: int


def validate_ballot(sb: StoredBallot, config: ElectionConfig, mpk) -> ExclusionReason | None:
    """Public single-ballot validity check (no duplicate handling).

    Returns ``None`` if the ballot is independently valid, else the
    :class:`ExclusionReason`. ``mpk`` is a decoded G2 point.
    """
    env = sb.envelope
    att = env.attestation

    # Wrong-election binding / structural mismatch.
    if env.election_id != config.election_id:
        return ExclusionReason.MALFORMED

    # Out-of-window (only when the adapter supplies an authoritative time).
    if sb.submitted_at is not None and not is_voting_open(config, sb.submitted_at):
        return ExclusionReason.OUT_OF_WINDOW

    # Attestation must bind this exact ballot (election, pseudonym, vk).
    if att.election_id != config.election_id or att.pseudonym != env.pseudonym or att.vk != env.vk:
        return ExclusionReason.INVALID_ATTESTATION
    if not verify_attestation(
        config.eligibility_key, att, election_id=config.election_id, max_weight=config.max_weight
    ):
        return ExclusionReason.INVALID_ATTESTATION

    # Ballot crypto: range/budget proofs + Schnorr signature.
    ok, reason = verify_ballot_crypto(
        mpk=mpk,
        election_id=env.election_id,
        pseudonym=env.pseudonym,
        vk_bytes=env.vk,
        ciphertext_bytes=[(ct.c1, ct.c2) for ct in env.ciphertexts],
        zk_proof=env.zk_proof,
        voter_signature=env.voter_signature,
        num_candidates=config.num_candidates,
        budget=config.budget,
    )
    if not ok:
        return ExclusionReason(reason)  # "MALFORMED" | "INVALID_PROOF" | "INVALID_SIGNATURE"
    return None


def _duplicate_losers(valid: list[StoredBallot], policy: DuplicatePolicy) -> set[int]:
    """Sequence numbers excluded as duplicates, per policy, over the ordered list."""
    keeper: dict[bytes, int] = {}  # pseudonym -> kept sequence number
    losers: set[int] = set()
    for sb in valid:  # already in stable total order
        pseud = sb.envelope.pseudonym
        if pseud not in keeper:
            keeper[pseud] = sb.sequence_number
            continue
        if policy is DuplicatePolicy.FIRST_WINS:
            losers.add(sb.sequence_number)  # the earlier one keeps its place
        else:  # LAST_WINS: the previous keeper loses, this one takes over
            losers.add(keeper[pseud])
            keeper[pseud] = sb.sequence_number
    return losers


def admit(ballots: list[StoredBallot], config: ElectionConfig, mpk_bytes: bytes) -> AdmissionResult:
    """Compute the admitted set and typed exclusions.

    ``ballots`` must be in the data layer's stable total order. ``mpk_bytes`` is
    the finalized election key (``FinalizedKey.pk_election``).
    """
    mpk = g2_from_compressed(mpk_bytes)

    exclusions: list[Exclusion] = []
    valid: list[StoredBallot] = []
    for sb in ballots:
        reason = validate_ballot(sb, config, mpk)
        if reason is None:
            valid.append(sb)
        else:
            exclusions.append(Exclusion(sequence_number=sb.sequence_number, reason=reason))

    losers = _duplicate_losers(valid, config.duplicate_policy)

    admitted: list[AdmittedBallot] = []
    for sb in valid:
        if sb.sequence_number in losers:
            exclusions.append(
                Exclusion(sequence_number=sb.sequence_number, reason=ExclusionReason.DUPLICATE_PSEUDONYM)
            )
        else:
            admitted.append(
                AdmittedBallot(
                    sequence_number=sb.sequence_number,
                    envelope=sb.envelope,
                    weight=sb.envelope.attestation.weight,
                )
            )

    exclusions.sort(key=lambda x: x.sequence_number)
    total_weight = sum(a.weight for a in admitted)
    return AdmissionResult(
        admitted=tuple(admitted),
        exclusions=tuple(exclusions),
        total_admitted_weight=total_weight,
    )
