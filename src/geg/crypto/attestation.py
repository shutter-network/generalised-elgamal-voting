"""``ATTESTATION_V1`` — the weighted eligibility credential.

A Schnorr-on-G1 signature by ``eligibility_key`` over a **domain-separated
transcript** of ``(election_id, pseudonym, vk, weight)``. This extends the prior
Wahlregister attestation (which covered ``(election_id, pseudonym, vk)`` as a
bare keccak concatenation with no domain separator and no weight) and is a
**distinct codec**, not a silent modification:

* the transcript is seeded with the label ``SHUTTER-VOTE-ATTEST-v1`` and every
  field is length-prefixed (the Merlin discipline), so nothing is ambiguous;
* ``weight`` is bound as a scalar, so the credential is inseparable from the
  weight it authorizes — the whole tally stays re-derivable from public artifacts.

The 80-byte wire form is the standard Schnorr encoding (``R ‖ s``). The signed
message is ``keccak256(transcript.preimage())``.
"""

from __future__ import annotations

from eth_utils import keccak

from geg.crypto import schnorr
from geg.crypto.params import ATTESTATION_LABEL
from geg.crypto.points import g1_from_compressed
from geg.crypto.transcript import Transcript


def _attestation_transcript(election_id: bytes, pseudonym: bytes, vk_bytes: bytes, weight: int) -> Transcript:
    if len(election_id) != 32:
        raise ValueError(f"electionId must be 32 bytes (got {len(election_id)})")
    if len(pseudonym) != 32:
        raise ValueError(f"pseudonym must be 32 bytes (got {len(pseudonym)})")
    if len(vk_bytes) != 48:
        raise ValueError(f"vk must be 48 bytes (got {len(vk_bytes)})")
    if weight < 1:
        raise ValueError(f"weight must be >= 1 (got {weight})")
    t = Transcript(ATTESTATION_LABEL)
    t.append("attest:electionId", election_id)
    t.append("attest:pseudonym", pseudonym)
    t.append("attest:vk", vk_bytes)
    t.append_scalar("attest:weight", weight)
    return t


def attestation_message(election_id: bytes, pseudonym: bytes, vk_bytes: bytes, weight: int) -> bytes:
    """The keccak256 digest the eligibility key signs for ``ATTESTATION_V1``."""
    return keccak(_attestation_transcript(election_id, pseudonym, vk_bytes, weight).preimage())


def sign_attestation(elig_sk: int, elig_vk, election_id: bytes, pseudonym: bytes,
                     vk_bytes: bytes, weight: int, *, k: int | None = None) -> bytes:
    """Issue an ``ATTESTATION_V1`` signature (80-byte ``R ‖ s``)."""
    msg = attestation_message(election_id, pseudonym, vk_bytes, weight)
    R, s = schnorr.sign(elig_sk, elig_vk, msg, k=k)
    return schnorr.encode(R, s)


def verify_attestation_sig(elig_vk_bytes: bytes, election_id: bytes, pseudonym: bytes,
                           vk_bytes: bytes, weight: int, signature: bytes) -> bool:
    """Verify an ``ATTESTATION_V1`` signature against ``eligibility_key``.

    Returns ``False`` (never raises) on any malformed input, so callers can treat
    a ``False`` uniformly as ``INVALID_ATTESTATION``.
    """
    try:
        if len(election_id) != 32 or len(pseudonym) != 32 or len(vk_bytes) != 48:
            return False
        if weight < 1:
            return False
        elig_vk = g1_from_compressed(elig_vk_bytes)
        R, s = schnorr.decode(signature)
        msg = attestation_message(election_id, pseudonym, vk_bytes, weight)
        return schnorr.verify(elig_vk, msg, R, s)
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
#  Legacy Wahlregister attestation (weightless; legacy interop)
#
#  The concept-doc-locked scheme: Schnorr-on-G1 over the bare concatenation
#  ``keccak256(electionId ‖ pseudonym ‖ vk)`` — no domain separator, no weight.
#  Carried for interop with existing Munich-style deployments. A legacy
#  credential is only valid at weight 1 (it does not authorize any other weight).
# --------------------------------------------------------------------------- #

def legacy_attestation_message(election_id: bytes, pseudonym: bytes, vk_bytes: bytes) -> bytes:
    """The weightless legacy preimage digest: ``keccak(electionId ‖ pseudonym ‖ vk)``."""
    if len(election_id) != 32 or len(pseudonym) != 32 or len(vk_bytes) != 48:
        raise ValueError("legacy attestation: bad field sizes")
    return keccak(election_id + pseudonym + vk_bytes)


def sign_attestation_legacy(elig_sk: int, elig_vk, election_id: bytes, pseudonym: bytes,
                            vk_bytes: bytes, *, k: int | None = None) -> bytes:
    """Issue a legacy (weightless) attestation signature (80-byte ``R ‖ s``)."""
    msg = legacy_attestation_message(election_id, pseudonym, vk_bytes)
    R, s = schnorr.sign(elig_sk, elig_vk, msg, k=k)
    return schnorr.encode(R, s)


def verify_attestation_legacy_sig(elig_vk_bytes: bytes, election_id: bytes, pseudonym: bytes,
                                  vk_bytes: bytes, signature: bytes) -> bool:
    """Verify a legacy weightless attestation. Returns ``False`` (never raises)."""
    try:
        elig_vk = g1_from_compressed(elig_vk_bytes)
        R, s = schnorr.decode(signature)
        msg = legacy_attestation_message(election_id, pseudonym, vk_bytes)
        return schnorr.verify(elig_vk, msg, R, s)
    except Exception:  # noqa: BLE001
        return False
