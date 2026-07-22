"""Keyper token-bootstrap crypto (sx-monorepo model, geg identity).

Two independent properties (neither substitutes for the other), matching
sx-monorepo's design:

  - **confidentiality** — ``x25519_seal`` / ``x25519_unseal``: an anonymous
    sealed box (ephemeral ECDH + HKDF + AES-GCM) so the coordinator can encrypt a
    token bundle *to* a keyper's X25519 public key. Anyone can seal to a public
    key, so this proves nothing about the sender.
  - **authenticity** — a secp256k1 EIP-191 signature over the plaintext payload,
    verified against the set of *pinned trusted-bootstrapper identities*. A keyper
    trusts more than one driver: the coordinator (drives DKG) and the tally
    aggregator (triggers decryption) each bootstrap with their **own** identity, so
    neither has to hold the other's key. Any signer whose recovered address is in
    the pinned set is accepted (same identity scheme geg uses for data-layer writes).

A :class:`NonceTracker` gives a bounded, TTL-based replay guard over bootstrap
payloads.
"""

from __future__ import annotations

import json
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

BOOTSTRAP_DST = b"GEG-KEYPER-TOKEN-BOOTSTRAP-v1"
_HKDF_INFO = b"geg-keyper-token-bootstrap-v1"
NONCE_WINDOW_S = 300


def canonical_payload_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _payload_digest(payload: dict) -> bytes:
    return keccak(BOOTSTRAP_DST + canonical_payload_bytes(payload))


def sign_payload(signer, payload: dict) -> bytes:
    """A trusted bootstrapper (coordinator or aggregator) signs a bootstrap payload
    with its secp256k1 identity (EIP-191).

    The key is passed as fixed 32-byte big-endian so a private key with a zero top
    byte doesn't serialize to <32 bytes (which eth_account rejects).
    """
    key = int(signer.private_key).to_bytes(32, "big")
    return bytes(Account.sign_message(encode_defunct(primitive=_payload_digest(payload)), key).signature)


def as_identity_set(trusted) -> set[bytes]:
    """Normalise a single 20-byte address or an iterable of them to a set of bytes."""
    if isinstance(trusted, (bytes, bytearray)):
        return {bytes(trusted)}
    return {bytes(t) for t in trusted}


def verify_payload(trusted_identities, payload: dict, signature: bytes) -> bool:
    """Verify the signer's recovered address is one of the pinned trusted
    bootstrapper identities (a single 20-byte address or an iterable). Never raises."""
    try:
        recovered = Account.recover_message(encode_defunct(primitive=_payload_digest(payload)), signature=signature)
        return bytes.fromhex(recovered[2:]) in as_identity_set(trusted_identities)
    except Exception:  # noqa: BLE001
        return False


def x25519_seal(plaintext: bytes, recipient_pubkey: X25519PublicKey) -> bytes:
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    recipient_pub = recipient_pubkey.public_bytes_raw()
    shared = eph.exchange(recipient_pubkey)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO + eph_pub + recipient_pub).derive(shared)
    nonce = os.urandom(12)
    return eph_pub + nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def x25519_unseal(sealed: bytes, recipient_privkey: X25519PrivateKey) -> bytes:
    if len(sealed) < 44:
        raise ValueError("sealed envelope too short")
    eph_pub, nonce, ct = sealed[:32], sealed[32:44], sealed[44:]
    shared = recipient_privkey.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    recipient_pub = recipient_privkey.public_key().public_bytes_raw()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO + eph_pub + recipient_pub).derive(shared)
    return AESGCM(key).decrypt(nonce, ct, None)


class NonceTracker:
    """Bounded TTL replay guard for bootstrap payload nonces."""

    def __init__(self, window_s: float = NONCE_WINDOW_S):
        self._window_s = window_s
        self._seen: dict[str, float] = {}

    def check_and_record(self, nonce: str, timestamp: int) -> bool:
        now = time.time()
        self._prune(now)
        if not nonce or abs(now - timestamp) > self._window_s:
            return False
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True

    def _prune(self, now: float) -> None:
        for n in [n for n, at in self._seen.items() if now - at > self._window_s]:
            del self._seen[n]
