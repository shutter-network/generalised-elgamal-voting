"""Keyper-to-keyper DKG P2P message schema.

DKG round-1 commitments and round-2 shares travel **directly between keypers**
over authenticated HTTP, never through the data layer: round-2 shares are
confidential (secret polynomial evaluations) and the data layer is public by
design. Only public DKG artifacts (result submissions, via
:class:`geg.envelopes.types.DKGResultSubmission`) touch the data layer.

This module fixes the message schema and the requirement that every P2P message
verifies against the sender's registered keyper identity. The **signature scheme
is an adapter concern** (EIP-191 ECDSA over Ethereum keys today, anything else
tomorrow, chosen consistently per deployment) — hence :class:`KeyperP2PTransport`
is abstract over signing/verification.

Invariants:

* Every message is signed by the dealer and verifies against the dealer's
  registered ``KeyperIdentity.signing_key`` at the dealer's index.
* Messages are **append-only per dealer per election**: a second, different
  submission from the same dealer is rejected.
* Feldman VSS verification in round 2 catches share/commitment mismatches and
  triggers the signed complaint/reveal flow (:class:`DKGRevealMessage`).

The ceremony is sequenced by the DKG coordinator daemon (a later slice):
``round1 -> distribute_commitments -> distribute_shares -> round2
(complaint loop) -> submit_dkg_result``. The coordinator holds no secrets; its
compromise affects liveness only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class DKGMessageType(str, Enum):
    """The kinds of P2P DKG messages."""

    COMMITMENTS = "commitments"  # round-1 Feldman commitments (public per dealer)
    SHARE = "share"  # round-2 secret share (confidential, one recipient)
    REVEAL = "reveal"  # signed complaint/reveal rebuttal during round 2


@dataclass(frozen=True)
class DKGCommitmentsMessage:
    """Round-1 Feldman commitments broadcast by a dealer.

    ``commitments`` are the public coefficient commitments (each a G2 point, 96
    bytes); every keyper stores them append-only per dealer and uses them to
    verify received shares in round 2.
    """

    election_id: bytes
    dealer_index: int
    commitments: tuple[bytes, ...]  # each G2, 96 bytes
    signature: bytes  # by the dealer's registered signing key


@dataclass(frozen=True)
class DKGShareMessage:
    """Round-2 confidential secret share from a dealer to one recipient.

    ``share`` is a scalar (the dealer's polynomial evaluated at the recipient's
    index), 32 bytes. Confidential — sent point-to-point, never to the data layer.
    """

    election_id: bytes
    dealer_index: int
    recipient_index: int
    share: bytes  # scalar, 32 bytes
    signature: bytes  # by the dealer's registered signing key


@dataclass(frozen=True)
class DKGRevealMessage:
    """Signed Feldman-VSS rebuttal: a dealer reveals a share during complaint
    resolution."""

    election_id: bytes
    dealer_index: int
    recipient_index: int
    revealed_share: bytes  # scalar, 32 bytes
    signature: bytes  # by the dealer's registered signing key


class KeyperP2PTransport(ABC):
    """Authenticated point-to-point transport between keypers.

    Signing and verification are abstract because the signature scheme is a
    per-deployment adapter concern. Implementations MUST verify every inbound
    message against the sender's registered ``KeyperIdentity.signing_key`` at the
    claimed ``dealer_index`` and enforce append-only-per-dealer semantics. Transport
    security (TLS) and endpoint authentication (bearer tokens) are deployment
    requirements for any multi-operator setup.
    """

    @abstractmethod
    def send_commitments(self, to_url: str, message: DKGCommitmentsMessage) -> None:
        """Deliver a signed round-1 commitments message to one peer."""

    @abstractmethod
    def send_share(self, to_url: str, message: DKGShareMessage) -> None:
        """Deliver a signed round-2 secret share to its single recipient."""

    @abstractmethod
    def send_reveal(self, to_url: str, message: DKGRevealMessage) -> None:
        """Deliver a signed complaint/reveal rebuttal to one peer."""

    @abstractmethod
    def verify_sender(self, message: object, expected_signing_key: bytes) -> bool:
        """Verify a message's signature against the dealer's registered identity."""
