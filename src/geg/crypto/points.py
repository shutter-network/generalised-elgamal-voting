"""BLS12-381 point arithmetic and compressed codecs.

Thin wrappers over ``py_arkworks_bls12381`` giving a uniform arithmetic surface
for both groups (G1 for Schnorr/attestations, G2 for ElGamal/DKG) plus the
zcash-format compressed codecs (G1 = 48 bytes, G2 = 96 bytes) with mandatory
subgroup checks on decode. These byte layouts are the on-the-wire contract.
"""

from __future__ import annotations

import secrets

from py_arkworks_bls12381 import G1Point, G2Point, Scalar

from geg.crypto.params import CURVE_ORDER, G1_BYTES, G2_BYTES

# Generators and identities.
G1 = G1Point()
G2 = G2Point()
Z1 = G1Point.identity()
Z2 = G2Point.identity()


def _scalar(n: int) -> Scalar:
    return Scalar(int(n) % CURVE_ORDER)


def mul(P, scalar: int):
    """Scalar multiplication ``scalar * P`` (works for G1 or G2)."""
    return P * _scalar(scalar)


def add(P, Q):
    return P + Q


def neg(P):
    return -P


def eq(P, Q) -> bool:
    return P == Q


def is_identity(P) -> bool:
    return P == Z1 if isinstance(P, G1Point) else P == Z2


def random_scalar() -> int:
    """Cryptographically random scalar in ``[1, CURVE_ORDER - 1]``."""
    return secrets.randbelow(CURVE_ORDER - 1) + 1


# --------------------------------------------------------------------------- #
#  Compressed codecs (zcash format, subgroup-checked on decode)
# --------------------------------------------------------------------------- #

def g2_to_compressed(P) -> bytes:
    b = bytes(P.to_compressed_bytes())
    if len(b) != G2_BYTES:
        raise ValueError(f"G2 compressed encoding produced {len(b)} bytes, expected {G2_BYTES}")
    return b


def g2_from_compressed(b: bytes):
    if len(b) != G2_BYTES:
        raise ValueError(f"Expected {G2_BYTES}-byte G2 compressed point, got {len(b)}")
    try:
        P = G2Point.from_compressed_bytes(bytes(b))
    except Exception as exc:  # noqa: BLE001 — normalise arkworks errors
        raise ValueError(f"Invalid G2 compressed encoding: {exc}") from exc
    if not P.is_in_subgroup():
        raise ValueError("G2 point is not in the prime-order subgroup")
    return P


def g1_to_compressed(P) -> bytes:
    b = bytes(P.to_compressed_bytes())
    if len(b) != G1_BYTES:
        raise ValueError(f"G1 compressed encoding produced {len(b)} bytes, expected {G1_BYTES}")
    return b


def g1_from_compressed(b: bytes):
    if len(b) != G1_BYTES:
        raise ValueError(f"Expected {G1_BYTES}-byte G1 compressed point, got {len(b)}")
    try:
        P = G1Point.from_compressed_bytes(bytes(b))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Invalid G1 compressed encoding: {exc}") from exc
    if not P.is_in_subgroup():
        raise ValueError("G1 point is not in the prime-order subgroup")
    return P
