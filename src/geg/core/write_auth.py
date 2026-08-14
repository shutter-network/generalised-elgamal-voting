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


# --- ballot write authorization (off-chain backends only) ------------------- #
#
# The chain authorizes ballot writes by `msg.sender` holding VOTE_PROXY_ROLE, so this
# digest exists for the memory/DB backends, which previously had **no** way to honour
# `config.gateway_keys` at all. Content-binding rather than op-only, so a
# relayed write cannot have its ballot swapped in flight — the same property the
# dkg-result / aggregate / decrypt-share digests above already have — and the one
# `authz.request_digest`'s empty payload lacked until `result_digest` below.

BALLOT_WRITE_DST = b"GEG-BALLOT-WRITE-v1"


def ballot_digest(election_id: bytes, ballot) -> bytes:
    """Digest a gateway signs to authorize writing ``ballot`` to ``election_id``.

    Binds the **whole** envelope via its canonical JSON encoding — including the
    attestation, which the voter's own Schnorr signature does not cover — so a gateway
    signature authorizes exactly the bytes it saw.
    """
    import json

    from geg.envelopes import codecs

    canonical = json.dumps(codecs.enc_ballot(ballot), sort_keys=True, separators=(",", ":"))
    return keccak(BALLOT_WRITE_DST + bytes(election_id) + canonical.encode("utf-8"))


def sign_ballot(private_key: int, election_id: bytes, ballot) -> bytes:
    """Sign a ballot write as an authorized gateway."""
    return sign_digest(private_key, ballot_digest(election_id, ballot))


# --- result write authorization (off-chain backends only) ------------------- #
#
# authz.request_digest` defaults `payload=b""`, so a result-publisher signature used to authorize the pair
# ("result", electionId) and nothing more — the totals it was taken over were not bound,
# and any holder of one such signature could pair it with *different* totals. The other
# request-signed ops are fully described by (op, electionId) and so need no payload:
# `cancel` has no body, and `tally_stall` / `tally_resume` encode their direction in the
# op string itself. On chain this is moot — `publishResult` is gated on msg.sender holding
# RESULT_PUBLISHER_ROLE, with no signature to bind.

RESULT_DST = b"GEG-RESULT-v1"


def result_digest(election_id: bytes, result) -> bytes:
    """Payload binding a result-publisher signature to the totals it publishes.

    Covers every field the artifact carries: the per-candidate totals, the t+1 keyper
    indices credited with decrypting them, and the BSGS bound they were recovered under.
    """
    packed = (
        RESULT_DST
        + bytes(election_id)
        + abi_encode(
            ["uint256[]", "uint256[]", "uint256"],
            [
                [int(t) for t in result.totals],
                [int(i) for i in result.keyper_indices],
                int(result.bsgs_bound),
            ],
        )
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


# --- DKG peer-to-peer authenticity (keyper↔keyper transport, never on chain) -- #
#
# Commitments and shares are exchanged directly between keypers during the ceremony;
# accusations/reveals resolve Feldman-VSS complaints. None of these go on chain (the
# contract sees only the final dkg-result / decrypt-share / aggregate), so — unlike
# the Solidity-mirrored digests above — they use a simple length-framed keccak, EIP-191
# signed and recovered against the accuser/dealer's config member address.

DKG_COMMITMENTS_DST = b"GEG-DKG-COMMITMENTS-v1"
DKG_SHARE_DST = b"GEG-DKG-SHARE-v1"
DKG_ACCUSE_DST = b"GEG-DKG-ACCUSE-v1"
DKG_REVEAL_DST = b"GEG-DKG-REVEAL-v1"

from geg.crypto.params import CURVE_ORDER  # noqa: E402


def dkg_commitments_digest(election_id: bytes, dealer_index: int, commitments: list[bytes]) -> bytes:
    """Digest a dealer signs over the Feldman commitments it broadcasts."""
    parts = [
        DKG_COMMITMENTS_DST, bytes(election_id), int(dealer_index).to_bytes(8, "big"),
        len(commitments).to_bytes(4, "big"), *(bytes(c) for c in commitments),
    ]
    return keccak(b"".join(parts))


def dkg_share_digest(election_id: bytes, dealer_index: int, recipient_index: int, share: int) -> bytes:
    """Digest a dealer signs over the secret share it deals to one recipient. The
    signature is verified against the *unsealed* scalar, independent of transport sealing."""
    parts = [
        DKG_SHARE_DST, bytes(election_id), int(dealer_index).to_bytes(8, "big"),
        int(recipient_index).to_bytes(8, "big"), (int(share) % CURVE_ORDER).to_bytes(32, "big"),
    ]
    return keccak(b"".join(parts))


def dkg_accusation_digest(election_id: bytes, accused_dealer_index: int, recipient_index: int) -> bytes:
    """Digest a complaining recipient signs to accuse a dealer of dealing a bad share.
    Bound to (election, accused dealer, recipient) so it can neither be replayed across
    elections nor redirected to unlock a different dealer's share. Carries **no** share
    value — it only *authorizes* a reveal, it does not disclose one."""
    parts = [
        DKG_ACCUSE_DST, bytes(election_id), int(accused_dealer_index).to_bytes(8, "big"),
        int(recipient_index).to_bytes(8, "big"),
    ]
    return keccak(b"".join(parts))


def dkg_reveal_digest(election_id: bytes, dealer_index: int, recipient_index: int, share: int) -> bytes:
    """Digest a dealer signs when it reveals (in rebuttal) the share it dealt to a
    recipient. Distinct DST from the share digest so a reveal signature can never be
    replayed as a share signature or vice versa."""
    parts = [
        DKG_REVEAL_DST, bytes(election_id), int(dealer_index).to_bytes(8, "big"),
        int(recipient_index).to_bytes(8, "big"), (int(share) % CURVE_ORDER).to_bytes(32, "big"),
    ]
    return keccak(b"".join(parts))


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
