"""Keyper token-bootstrap crypto (geg identity).

Two independent properties (neither substitutes for the other):

  - **confidentiality** — ``x25519_seal`` / ``x25519_unseal``: an anonymous
    sealed box (ephemeral ECDH + HKDF + AES-GCM) so the coordinator can encrypt a
    token bundle *to* a keyper's X25519 public key. Anyone can seal to a public
    key, so this proves nothing about the sender.
  - **authenticity** — a secp256k1 EIP-191 signature over the plaintext payload,
    verified against the keyper's *pinned trusted-bootstrapper identities*. The
    coordinator is the sole keyper bootstrapper: a signer whose recovered address is
    in the pinned set is accepted (same identity scheme geg uses for data-layer writes).

A :class:`NonceTracker` gives a bounded, TTL-based replay guard over bootstrap
payloads.
"""

from __future__ import annotations

import base64
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

from geg.crypto.params import CURVE_ORDER

BOOTSTRAP_DST = b"GEG-KEYPER-TOKEN-BOOTSTRAP-v1"
_HKDF_INFO = b"geg-keyper-token-bootstrap-v1"
NONCE_WINDOW_S = 300

# Domain tag a keyper self-signs its X25519 encryption pubkey under, binding it to
# its secp256k1 keyper identity — so a key relayed via the coordinator's peers map
# can be verified against the keyper's config member address before anyone seals to it.
ENC_PUBKEY_DST = b"GEG-ENC-PUBKEY-v1"
# Domain tag prefixed to the *plaintext* inside a sealed DKG share, so a sealed
# share can never be unsealed and interpreted as some other sealed payload type
# that uses the same X25519 key (e.g. an /auth/bootstrap envelope).
SHARE_SEAL_DST = b"GEG-DKG-SHARE-SEAL-v1"


def canonical_payload_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _payload_digest(payload: dict) -> bytes:
    return keccak(BOOTSTRAP_DST + canonical_payload_bytes(payload))


def sign_payload(signer, payload: dict) -> bytes:
    """The trusted bootstrapper (the coordinator) signs a bootstrap payload
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


# --- encryption-pubkey binding (verify-before-seal) ------------------------- #

def enc_pubkey_hash(pubkey_bytes: bytes) -> bytes:
    """Digest a keyper binds its X25519 encryption pubkey under (EIP-191-signed with
    its secp256k1 keyper key)."""
    return keccak(ENC_PUBKEY_DST + bytes(pubkey_bytes))


def sign_encryption_pubkey(signer, pubkey_bytes: bytes) -> bytes:
    """A keyper self-signs its X25519 encryption pubkey, binding it to its secp256k1
    identity. Exposed on /status so a relayed key can be verified before use."""
    key = int(signer.private_key).to_bytes(32, "big")
    return bytes(Account.sign_message(encode_defunct(primitive=enc_pubkey_hash(pubkey_bytes)), key).signature)


def _addr_hex(address) -> str:
    """Normalise a 20-byte address (bytes) or hex string to lowercase 0x-hex."""
    if isinstance(address, (bytes, bytearray)):
        return "0x" + bytes(address).hex()
    s = str(address).lower()
    return s if s.startswith("0x") else "0x" + s


def verify_encryption_pubkey(address, pubkey_hex: str, sig_hex: str) -> X25519PublicKey:
    """Verify a keyper's self-published ``encryption_pubkey`` is bound to the given
    (already-trusted, e.g. config member) signing ``address``, and return the parsed
    X25519 public key.

    Used by the coordinator (before sealing a keyper's bootstrap bundle) and by a
    dealer (before sealing a share to a peer — so a key delivered via the coordinator's
    peers map can't be substituted). Raises ``ValueError`` on any mismatch; callers
    must treat that as "not usable" and never seal to an unverified key.
    """
    pubkey_bytes = bytes.fromhex(pubkey_hex.removeprefix("0x"))
    msg = encode_defunct(primitive=enc_pubkey_hash(pubkey_bytes))
    recovered = Account.recover_message(msg, signature=bytes.fromhex(sig_hex.removeprefix("0x")))
    if recovered.lower() != _addr_hex(address):
        raise ValueError(f"encryption_pubkey signature mismatch for {_addr_hex(address)}: recovered {recovered}")
    return X25519PublicKey.from_public_bytes(pubkey_bytes)


# --- DKG share sealing (confidentiality on the wire) ------------------------ #

def seal_share(share: int, recipient_pubkey: X25519PublicKey) -> str:
    """Seal a secret DKG share to a recipient keyper's X25519 public key (anonymous
    sealed box), returning base64 for JSON transport.

    Confidentiality only — authenticity/binding to (election, dealer, recipient) comes
    from the dealer's separate EIP-191 signature over the plaintext share value. The
    plaintext is domain-tagged (:data:`SHARE_SEAL_DST`) so it cannot be cross-interpreted
    as another sealed payload type that uses the same key.
    """
    plaintext = SHARE_SEAL_DST + (int(share) % CURVE_ORDER).to_bytes(32, "big")
    return base64.b64encode(x25519_seal(plaintext, recipient_pubkey)).decode()


def unseal_share(sealed_b64: str, recipient_privkey: X25519PrivateKey) -> int:
    """Inverse of :func:`seal_share`. Raises on a tampered box (AES-GCM auth failure),
    a wrong recipient key, or a domain-tag / length mismatch."""
    plaintext = x25519_unseal(base64.b64decode(sealed_b64), recipient_privkey)
    if not plaintext.startswith(SHARE_SEAL_DST):
        raise ValueError("sealed share domain-tag mismatch")
    body = plaintext[len(SHARE_SEAL_DST):]
    if len(body) != 32:
        raise ValueError("sealed share has unexpected length")
    return int.from_bytes(body, "big")


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
