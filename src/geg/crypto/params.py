"""Fixed parameters of the protocol-v1 crypto suite.

BLS12-381: ElGamal ciphertexts and DKG artifacts live in **G2**; voter Schnorr
signatures and attestations live in **G1**. Scalars are integers mod
:data:`CURVE_ORDER`, serialized big-endian in 32 bytes. Hash is keccak256
throughout. Domain-separation tags and fixed byte sizes are pinned here because
they are the interop contract — changing any of them is a ``protocol_version``
bump, never an edit.
"""

from __future__ import annotations

# BLS12-381 scalar field order (subgroup order Q).
CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513

# Canonical compressed point sizes (zcash format, subgroup-checked on decode).
G1_BYTES = 48  # voter vk, Schnorr R, eligibility/attestation keys
G2_BYTES = 96  # ElGamal C1/C2, sigma, committee PKs, DKG commitments

# Composite wire sizes.
SCALAR_BYTES = 32
SCHNORR_BYTES = 80  # R (48) || s (32)
DLEQ_BYTES = 64  # e (32) || z (32)

# Domain-separation tags (byte strings) — fixed for protocol v1.
DST_FIAT_SHAMIR = b"SHUTTER-VOTE-FS-v1"
DST_SCHNORR = b"SHUTTER-VOTE-SCHNORR-v1"

# Transcript labels.
BALLOT_LABEL = "SHUTTER-VOTE-BALLOT-v1"
ONCHAIN_DECRYPT_LABEL = "SHUTTER-VOTE-DECRYPT-v1"
ATTESTATION_LABEL = "SHUTTER-VOTE-ATTEST-v1"  # ATTESTATION_V1 (weighted)

# Ballot-validity-proof codec constants.
BVP_VERSION = 0x01
VARIANT_A_BYTE = 0x41  # 'A'
VARIANT_B_BYTE = 0x42  # 'B' (conformance level 2)
BUDGET_EXACT_TAG = 0x00
BUDGET_AT_MOST_TAG = 0x01
BRANCH_SIZE = 2 * G2_BYTES + 2 * SCALAR_BYTES  # 256: a1 || a2 || e || z


# --------------------------------------------------------------------------- #
#  Small encoding helpers shared across the crypto modules
# --------------------------------------------------------------------------- #

def u16be(n: int) -> bytes:
    return int(n).to_bytes(2, "big")


def u32be(n: int) -> bytes:
    return int(n).to_bytes(4, "big")


def scalar_to_bytes(s: int) -> bytes:
    """32-byte big-endian encoding of a scalar reduced mod ``CURVE_ORDER``."""
    return (int(s) % CURVE_ORDER).to_bytes(SCALAR_BYTES, "big")


def wide_reduce(b: bytes) -> int:
    """Reduce a wide byte string to a scalar (used by dual-keccak challenges)."""
    return int.from_bytes(b, "big") % CURVE_ORDER
