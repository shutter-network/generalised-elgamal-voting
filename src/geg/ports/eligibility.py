"""``EligibilityService`` — the authority on who may vote and with what weight
.

The core protocol never sees this service's internals; it interacts through
exactly one artifact, the ``ATTESTATION_V1`` credential
(:class:`geg.envelopes.types.Attestation`): a Schnorr-on-G1 signature by
``eligibility_key`` over a domain-separated transcript of
``(election_id, pseudonym, vk, weight)``.

Two halves, with very different normativity:

* **Issuance is adapter-specific and out of scope for the protocol.** How a voter
  obtains an attestation — an OIDC flow, a wallet signature challenge, in-person
  registration — is each implementation's own business. This ABC fixes only that
  an adapter *can* issue, and over which tuple; it does not constrain how the
  adapter authenticates the request.
* **Verification is fully normative.** One canonical preimage, one signature
  scheme per protocol version. Verification is a pure function (no service state),
  so it lives as :func:`verify_attestation` rather than on the service — auditors
  and the tally pipeline call it without any eligibility service present.

Reference adapters: a Wahlregister-style adapter (weight fixed
to 1) and a wallet-based adapter (EIP-712 challenge + on-chain voting power →
``weight``). Both are later slices; this module is the contract only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from geg.envelopes.types import Attestation


@dataclass(frozen=True)
class AttestationRequest:
    """Inputs an adapter binds into an attestation.

    The ``pseudonym`` construction is adapter-owned (e.g.
    ``keccak256(address || election_id)`` in a wallet adapter, an opaque
    registry-issued value in a Wahlregister adapter); the core relies only on its
    uniqueness per ``(election_id, voter)`` and unlinkability across elections.
    ``weight`` is resolved by the adapter (1 for one-person-one-vote; voting power
    for a wallet adapter) and must satisfy ``1 <= weight <= max_weight`` for the
    target election.
    """

    election_id: bytes
    pseudonym: bytes
    vk: bytes  # voter's ephemeral Schnorr verification key (G1, 48 bytes)
    weight: int
    # Monotonic per-(election, pseudonym) re-vote counter (1 for a first vote, then
    # 2, 3, …). The issuing service allocates it; the tally picks the highest-nonce
    # ballot per pseudonym so a replayed old ballot cannot override a genuine re-vote.
    nonce: int = 1


class EligibilityService(ABC):
    """Issuing interface for ``ATTESTATION_V1``. Verification is :func:`verify_attestation`."""

    @abstractmethod
    def issue_attestation(self, request: AttestationRequest) -> Attestation:
        """Issue a signed ``ATTESTATION_V1`` for an authenticated, eligible voter.

        How the caller proved eligibility (and how ``request`` was authenticated)
        is entirely the adapter's concern. The returned attestation binds
        ``(election_id, pseudonym, vk, weight)`` under ``eligibility_key``.
        """


def verify_attestation(
    eligibility_key: bytes,
    attestation: Attestation,
    *,
    election_id: bytes,
    max_weight: int,
) -> bool:
    """Normative ``ATTESTATION_V1`` verification.

    Dispatches on ``attestation.scheme``:

    * ``V1`` — verifies the Schnorr-on-G1 signature over the domain-separated
      transcript of ``(election_id, pseudonym, vk, weight, nonce)``.
    * ``LEGACY`` — verifies the weightless ``keccak(electionId‖pseudonym‖vk)``
      signature; valid only at ``weight == 1`` (it authorizes no other weight).

    Also checks that the attestation binds the expected ``election_id`` and that
    ``1 <= weight <= max_weight``. Returns ``False`` (never raises) on any
    failure, so callers treat it uniformly as ``INVALID_ATTESTATION``.
    """
    # Import here to keep the port module importable without the crypto backend.
    from geg.crypto.attestation import verify_attestation_legacy_sig, verify_attestation_sig
    from geg.envelopes.types import AttestationScheme

    if attestation.election_id != election_id:
        return False
    if not (1 <= attestation.weight <= max_weight):
        return False

    if attestation.scheme is AttestationScheme.V1:
        return verify_attestation_sig(
            eligibility_key,
            attestation.election_id,
            attestation.pseudonym,
            attestation.vk,
            attestation.weight,
            attestation.nonce,
            attestation.signature,
        )
    if attestation.scheme is AttestationScheme.LEGACY:
        # Legacy credentials are weightless — they only authorize weight 1.
        if attestation.weight != 1:
            return False
        return verify_attestation_legacy_sig(
            eligibility_key,
            attestation.election_id,
            attestation.pseudonym,
            attestation.vk,
            attestation.signature,
        )
    return False
