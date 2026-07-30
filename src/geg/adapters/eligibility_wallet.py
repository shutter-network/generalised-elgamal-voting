"""Wallet-based ``EligibilityService`` adapter.

Maps the Snapshot X flow onto the generalised eligibility port: a voter proves
control of an Ethereum address by signing an **EIP-712 challenge** bound to
``(electionId, vk)``; the adapter derives an unlinkable per-election
**pseudonym** ``keccak256(address ‖ electionId)``, reads the address's **voting
power**, and issues an ``ATTESTATION_V1`` with ``weight = min(votingPower,
maxWeight)``. The verifying side is unchanged — the credential this adapter
issues verifies under the same normative ``verify_attestation`` as any other.

The EIP-712 binding gives replay/transfer resistance for free: a signature over
``(electionA, vk1)`` reused for a different election or ballot key recovers a
*different* address (with no voting power), so it is rejected.

Voting power is read through an injected ``voting_power`` callable
(``address_bytes -> int``) — the seam a production deployment fills with a
chain/strategy read (Snapshot's standard scoring). This keeps the adapter
self-contained and testable; a chain-backed implementation plugs in without
touching the protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from geg.crypto import attestation as att_crypto
from geg.crypto import schnorr
from geg.crypto.points import g1_to_compressed
from geg.envelopes.types import Attestation, AttestationScheme
from geg.ports.eligibility import EligibilityService

VotingPowerSource = Callable[[bytes], int]


class EligibilityError(ValueError):
    """Raised when a wallet challenge is invalid or the voter is ineligible."""


class NotEligible(EligibilityError):
    """Raised when the recovered address has no voting power."""


@dataclass(frozen=True)
class WalletAttestationRequest:
    """A wallet voter's request: prove control of an address and bind a ballot key.

    ``signature`` is the voter's EIP-712 signature over the ``(election_id, vk)``
    challenge (see :meth:`WalletEligibilityService.challenge`). The pseudonym and
    weight are *derived* by the service, not supplied by the caller.
    """

    election_id: bytes
    vk: bytes  # voter's ephemeral Schnorr verification key (G1, 48 bytes)
    signature: bytes


class WalletEligibilityService(EligibilityService):
    def __init__(
        self,
        elig_sk: int,
        voting_power: VotingPowerSource,
        *,
        max_weight: int,
        chain_id: int,
        domain_name: str = "GEG Eligibility",
        domain_version: str = "1",
        verifying_contract: str | None = None,
        prevent_reissue: bool = True,
    ):
        self._sk, self._vk = schnorr.keygen(elig_sk)
        self.eligibility_key: bytes = g1_to_compressed(self._vk)
        self._voting_power = voting_power
        self._max_weight = max_weight
        self._chain_id = chain_id
        self._domain_name = domain_name
        self._domain_version = domain_version
        self._verifying_contract = verifying_contract
        self._prevent_reissue = prevent_reissue
        self._issued: set[tuple[bytes, bytes]] = set()  # (election_id, address)

    # -- EIP-712 challenge -------------------------------------------------- #

    def _typed_data(self, election_id: bytes, vk: bytes):
        domain = {"name": self._domain_name, "version": self._domain_version, "chainId": self._chain_id}
        if self._verifying_contract is not None:
            domain["verifyingContract"] = self._verifying_contract
        types = {
            "EligibilityChallenge": [
                {"name": "electionId", "type": "bytes32"},
                {"name": "vk", "type": "bytes"},
            ]
        }
        message = {"electionId": election_id, "vk": vk}
        return domain, types, message

    def challenge(self, election_id: bytes, vk: bytes):
        """Return the EIP-712 ``SignableMessage`` the voter's wallet signs."""
        return encode_typed_data(*self._typed_data(election_id, vk))

    def _recover_address(self, election_id: bytes, vk: bytes, signature: bytes) -> bytes:
        try:
            signable = self.challenge(election_id, vk)
            addr = Account.recover_message(signable, signature=signature)
        except Exception as exc:  # noqa: BLE001 — malformed signature
            raise EligibilityError(f"invalid EIP-712 challenge signature: {exc}") from exc
        return bytes.fromhex(addr[2:])

    # -- pseudonym ---------------------------------------------------------- #

    @staticmethod
    def pseudonym_for(address: bytes, election_id: bytes) -> bytes:
        """Unlinkable per-election pseudonym: ``keccak256(address ‖ electionId)``."""
        return keccak(bytes(address) + bytes(election_id))

    # -- issuance ----------------------------------------------------------- #

    def issue_for_wallet(self, election_id: bytes, vk: bytes, signature: bytes) -> Attestation:
        if len(election_id) != 32:
            raise EligibilityError("election_id must be 32 bytes")
        if len(vk) != 48:
            raise EligibilityError("vk must be 48 bytes")

        address = self._recover_address(election_id, vk, signature)
        vp = int(self._voting_power(address))
        if vp <= 0:
            raise NotEligible(f"address {address.hex()} has no voting power")

        if self._prevent_reissue and (election_id, address) in self._issued:
            raise EligibilityError("attestation already issued for this address in this election")

        weight = min(vp, self._max_weight)  # clamp — the maxWeight BSGS guard
        pseudonym = self.pseudonym_for(address, election_id)
        sig = att_crypto.sign_attestation(self._sk, self._vk, election_id, pseudonym, vk, weight)
        self._issued.add((election_id, address))
        return Attestation(
            election_id=election_id, pseudonym=pseudonym, vk=vk,
            weight=weight, signature=sig, scheme=AttestationScheme.V1,
        )

    def issue_attestation(self, request: WalletAttestationRequest) -> Attestation:
        """Port entry point. ``request`` must be a :class:`WalletAttestationRequest`
        (the wallet flow derives pseudonym + weight itself)."""
        if not isinstance(request, WalletAttestationRequest):
            raise EligibilityError(
                "WalletEligibilityService requires a WalletAttestationRequest (electionId, vk, signature)"
            )
        return self.issue_for_wallet(request.election_id, request.vk, request.signature)
