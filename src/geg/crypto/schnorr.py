"""Single-point Schnorr signatures over G1.

``vk = sk·P1``; ``sign: R = k·P1, e = H(R‖vk‖msg), s = k + e·sk``; ``verify:
s·P1 == R + e·vk``. Chosen over BLS so verification stays in G1 without a pairing.
``H`` is the dual-keccak :func:`hash_to_scalar` with DST ``SHUTTER-VOTE-SCHNORR-v1``.
Used for the voter ballot signature and the ATTESTATION_V1 eligibility signature.
"""

from __future__ import annotations

from geg.crypto.params import CURVE_ORDER, DST_SCHNORR, SCHNORR_BYTES, scalar_to_bytes
from geg.crypto.points import (
    G1,
    Z1,
    g1_from_compressed,
    g1_to_compressed,
    mul,
    random_scalar,
)
from geg.crypto.transcript import hash_to_scalar


def _challenge(R, vk, msg: bytes) -> int:
    return hash_to_scalar(DST_SCHNORR, g1_to_compressed(R), g1_to_compressed(vk), bytes(msg))


def keygen(sk: int | None = None) -> tuple[int, object]:
    """Generate a keypair ``(sk, vk)`` with ``vk = sk·P1``. Rejects ``sk == 0``."""
    if sk is None:
        sk = random_scalar()
    sk %= CURVE_ORDER
    if sk == 0:
        raise ValueError("schnorr keygen: sk must be non-zero mod CURVE_ORDER")
    return sk, mul(G1, sk)


def sign(sk: int, vk, msg: bytes, k: int | None = None) -> tuple[object, int]:
    """Produce ``(R, s)`` with ``s·P1 == R + e·vk``. Optional ``k`` for vectors."""
    if k is None:
        k = random_scalar()
    k %= CURVE_ORDER
    R = mul(G1, k)
    e = _challenge(R, vk, msg)
    s = (k + e * (sk % CURVE_ORDER)) % CURVE_ORDER
    return R, s


def verify(vk, msg: bytes, R, s: int) -> bool:
    """Check ``s·P1 == R + e·vk``. Rejects identity ``vk`` (else any sig passes)."""
    if vk == Z1:
        return False
    e = _challenge(R, vk, msg)
    return mul(G1, s) == R + mul(vk, e)


def encode(R, s: int) -> bytes:
    """80-byte wire form: ``R (48) ‖ s (32)``."""
    return g1_to_compressed(R) + scalar_to_bytes(s)


def decode(b: bytes) -> tuple[object, int]:
    if len(b) != SCHNORR_BYTES:
        raise ValueError(f"Expected {SCHNORR_BYTES}-byte Schnorr signature, got {len(b)}")
    return g1_from_compressed(b[:48]), int.from_bytes(b[48:], "big")
