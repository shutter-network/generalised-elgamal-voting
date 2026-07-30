"""Content-binding write signatures for keyper writes.

A keyper signs the **content** of its write (the DKG result, or its decryption
shares), not a generic request. The digest is byte-identical to the contract's
meta-tx digest, so one keyper signature is verified the same way by every
backend: the in-memory/database stores recover the signer and check committee
membership; the blockchain store relays the signature to the ``...Signed``
contract method, which ``ecrecover``s the same digest. This is what makes keypers
backend-agnostic *and* preserves on-chain per-keyper authorship.

Digests mirror the Solidity exactly (see ``ElectionDKG.sol`` /
``ElectionDecryption.sol``):

    dkg-result     = keccak256("GEG-DKG-RESULT-v1" ‖ electionId ‖ pkElection ‖ abi.encode(committeePKs))
    decrypt-share  = keccak256("GEG-DECRYPT-SHARE-v1" ‖ electionId ‖ abi.encode(shares) ‖ abi.encode(proofs))

signed as an EIP-191 personal-sign message so ``ecrecover`` + OZ ``ECDSA`` agree.
``electionId`` is the 32-byte value (== the uint256 electionId on chain).
"""

from __future__ import annotations

from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

DKG_RESULT_DST = b"GEG-DKG-RESULT-v1"
DECRYPT_SHARE_DST = b"GEG-DECRYPT-SHARE-v1"
AGGREGATE_DST = b"GEG-AGGREGATE-v1"

# Exclusion reason → uint8 code for the aggregate digest. Order MUST match the
# Solidity `enum ExclusionReason` in VotingTypes.sol (both are declaration order).
from geg.envelopes.types import ExclusionReason  # noqa: E402  (core already depends on envelopes via aggregation)

_EXCLUSION_CODE = {reason: index for index, reason in enumerate(ExclusionReason)}


def dkg_result_digest(election_id: bytes, pk_election: bytes, committee_pks: list[bytes]) -> bytes:
    packed = DKG_RESULT_DST + bytes(election_id) + bytes(pk_election) + abi_encode(["bytes[]"], [list(committee_pks)])
    return keccak(packed)


def decryption_share_digest(election_id: bytes, shares: list[bytes], proofs: list[tuple[int, int]]) -> bytes:
    packed = (
        DECRYPT_SHARE_DST
        + bytes(election_id)
        + abi_encode(["bytes[]"], [list(shares)])
        + abi_encode(["(uint256,uint256)[]"], [[(int(e), int(z)) for (e, z) in proofs]])
    )
    return keccak(packed)


# --- sign / recover -------------------------------------------------------- #

def sign_digest(private_key: int, digest: bytes) -> bytes:
    """EIP-191 personal-sign over a 32-byte digest; returns the 65-byte signature.

    The key is passed as fixed 32-byte big-endian: an ``int`` whose top byte is
    zero would otherwise serialize to <32 bytes and eth_account would reject it.
    """
    key = int(private_key).to_bytes(32, "big")
    return bytes(Account.sign_message(encode_defunct(primitive=digest), key).signature)


def recover_digest(digest: bytes, signature: bytes) -> bytes:
    """Recover the 20-byte signer address from a digest signature."""
    addr = Account.recover_message(encode_defunct(primitive=digest), signature=signature)
    return bytes.fromhex(addr[2:])


def sign_dkg_result(private_key: int, election_id: bytes, pk_election: bytes, committee_pks: list[bytes]) -> bytes:
    return sign_digest(private_key, dkg_result_digest(election_id, pk_election, committee_pks))


def sign_decryption_share(private_key: int, election_id: bytes, shares: list[bytes], proofs: list[tuple[int, int]]) -> bytes:
    return sign_digest(private_key, decryption_share_digest(election_id, shares, proofs))


# --- aggregate (keyper-quorum, mirrors the DKG-result quorum) --------------- #
#
# The keyper content-signs the FULL aggregate artifact (aggregates + admitted set +
# exclusions + total weight). Backends recover the keyper from this signature and
# count byte-identical artifacts by the same digest — canonical at t+1. The chain
# `submitAggregateSigned` re-derives the same digest over the EncryptedTally struct.
#
#   aggregate = keccak256("GEG-AGGREGATE-v1" ‖ electionId ‖ abi.encode(EncryptedTally))
#
# where EncryptedTally is the single struct/tuple
#   ((bytes,bytes)[] aggregates, uint256[] admitted, (uint256,uint8)[] exclusions, uint256 total).
# One ABI-encode of the whole struct (matching Solidity ``abi.encode(aggregate)``) — this
# keeps the Election contract under the EIP-170 code-size limit vs. four field-wise encodes.

_TALLY_ABI = "((bytes,bytes)[],uint256[],(uint256,uint8)[],uint256)"


def aggregate_digest(
    election_id: bytes,
    aggregates: list[tuple[bytes, bytes]],
    admitted: list[int],
    exclusions: list[tuple[int, "ExclusionReason"]],
    total_admitted_weight: int,
) -> bytes:
    tally = (
        [(bytes(c1), bytes(c2)) for (c1, c2) in aggregates],
        [int(s) for s in admitted],
        [(int(seq), _EXCLUSION_CODE[reason]) for (seq, reason) in exclusions],
        int(total_admitted_weight),
    )
    packed = AGGREGATE_DST + bytes(election_id) + abi_encode([_TALLY_ABI], [tally])
    return keccak(packed)


def _aggregate_fields(aggregate):
    """Unpack an ``AggregateArtifact`` into the digest's primitive fields."""
    return (
        [(ct.c1, ct.c2) for ct in aggregate.aggregates],
        list(aggregate.admitted),
        [(x.sequence_number, x.reason) for x in aggregate.exclusions],
        aggregate.total_admitted_weight,
    )


def aggregate_digest_of(election_id: bytes, aggregate) -> bytes:
    """Digest of an ``AggregateArtifact`` (used by keyper to sign, backends to verify)."""
    aggs, admitted, exclusions, total = _aggregate_fields(aggregate)
    return aggregate_digest(election_id, aggs, admitted, exclusions, total)


def sign_aggregate(private_key: int, election_id: bytes, aggregate) -> bytes:
    return sign_digest(private_key, aggregate_digest_of(election_id, aggregate))
