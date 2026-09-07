"""Stub ``EligibilityService`` adapter.

A development eligibility service that issues attestations to any request
(fixed or request-supplied weight). It authenticates nobody — issuance
authentication is exactly what real adapters (wallet/EIP-712, OIDC, Wahlregister)
add. Its value is that it drives the tally pipeline end-to-end and demonstrates
the port: the verifying side (``verify_attestation``) is identical regardless of
which adapter issued the credential.

Mints the weighted ``ATTESTATION_V1``.
"""

from __future__ import annotations

from geg.crypto import attestation as att_crypto
from geg.crypto import schnorr
from geg.crypto.points import g1_to_compressed
from geg.envelopes.types import Attestation, AttestationScheme
from geg.ports.eligibility import AttestationRequest, EligibilityService


class StubEligibilityService(EligibilityService):
    def __init__(self, elig_sk: int, *, scheme: AttestationScheme = AttestationScheme.V1,
                 fixed_weight: int | None = None):
        self._sk, self._vk = schnorr.keygen(elig_sk)
        self.eligibility_key: bytes = g1_to_compressed(self._vk)
        self._scheme = scheme
        self._fixed_weight = fixed_weight

    def issue_attestation(self, request: AttestationRequest) -> Attestation:
        weight = self._fixed_weight if self._fixed_weight is not None else request.weight
        sig = att_crypto.sign_attestation(
            self._sk, self._vk, request.election_id, request.pseudonym, request.vk, weight, request.nonce
        )
        return Attestation(
            election_id=request.election_id, pseudonym=request.pseudonym, vk=request.vk,
            weight=weight, signature=sig, scheme=AttestationScheme.V1, nonce=request.nonce,
        )
