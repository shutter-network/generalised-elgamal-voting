"""Write-authorization identities — secp256k1 / ecrecover.

Unified with the on-chain authorization model: a write identity is an **Ethereum
secp256k1 key**, its ``identity`` is the 20-byte address, and a write is
authorized by an EIP-191 signature that the verifier recovers with ``ecrecover``.
The same identity/signature works for the in-memory, database (verify by
``ecrecover``), and blockchain (relayed as a meta-tx the contract ``ecrecover``s)
data layers, so keypers/services are backend-agnostic.

This is defense-in-depth against spam, **not a trust anchor** — every stored
artifact is self-verifying. Voter **ballot** and **attestation** keys are
unrelated and remain Schnorr-G1 (see :mod:`geg.crypto`).
"""

from __future__ import annotations

from dataclasses import dataclass

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak


def request_digest(op: str, election_id: bytes, payload: bytes = b"") -> bytes:
    """32-byte digest a write signature is taken over."""
    return keccak(op.encode("utf-8") + b"|" + election_id + b"|" + payload)


def sign_request(private_key: int, op: str, election_id: bytes, payload: bytes = b"") -> bytes:
    """Sign a write request (EIP-191 over the digest); returns the 65-byte signature.

    The key is passed as fixed 32-byte big-endian so an ``int`` with a zero top
    byte doesn't serialize to <32 bytes (which eth_account rejects).
    """
    key = int(private_key).to_bytes(32, "big")
    signed = Account.sign_message(encode_defunct(primitive=request_digest(op, election_id, payload)), key)
    return bytes(signed.signature)


def register_digest(config) -> bytes:
    """Digest a register signature is taken over: the canonical config with
    ``election_id`` zeroed (the backend assigns the next sequential id, so the admin
    authorizes the rest of the *config content*; both signer and verifier zero the id
    placeholder so whatever the caller supplies for it is irrelevant to the signature).
    """
    import json

    from geg.envelopes import codecs

    # Zero the placeholder electionId in the *encoded dict* (the backend assigns the id).
    d = codecs.enc_config(config)
    d["electionId"] = codecs.enc_bytes(b"\x00" * 32)
    return keccak(json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def sign_register(private_key: int, config) -> bytes:
    """Sign a registration request (EIP-191 over the config digest)."""
    key = int(private_key).to_bytes(32, "big")
    return bytes(Account.sign_message(encode_defunct(primitive=register_digest(config)), key).signature)


def verify_register(admin_key: bytes, signature: bytes, config) -> bool:
    """Recover the register signer and check it equals ``admin_key``. Never raises."""
    try:
        recovered = Account.recover_message(
            encode_defunct(primitive=register_digest(config)), signature=signature
        )
        return bytes.fromhex(recovered[2:]) == bytes(admin_key)
    except Exception:  # noqa: BLE001
        return False


def verify_request(identity: bytes, signature: bytes, op: str, election_id: bytes, payload: bytes = b"") -> bool:
    """Recover the signer and check it equals ``identity`` (a 20-byte address). Never raises."""
    try:
        recovered = Account.recover_message(
            encode_defunct(primitive=request_digest(op, election_id, payload)), signature=signature
        )
        return bytes.fromhex(recovered[2:]) == bytes(identity)
    except Exception:  # noqa: BLE001
        return False


@dataclass
class Signer:
    """A write identity: an Ethereum secp256k1 key whose ``identity`` is its address."""

    account: object  # eth_account LocalAccount

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Account.create())

    @classmethod
    def from_sk(cls, sk: int) -> "Signer":
        return cls(Account.from_key(int(sk).to_bytes(32, "big")))

    @property
    def identity(self) -> bytes:
        return bytes.fromhex(self.account.address[2:])

    @property
    def address(self) -> str:
        return self.account.address

    @property
    def private_key(self) -> int:
        return int.from_bytes(self.account.key, "big")

    def sign(self, op: str, election_id: bytes, payload: bytes = b"") -> bytes:
        return sign_request(self.private_key, op, election_id, payload)

    def sign_register(self, config) -> bytes:
        return sign_register(self.private_key, config)
