"""Content-binding write signatures for keyper writes (DESIGN.md §5.1, §5.3).

A keyper signs the **content** of its write (the DKG result, or its decryption
shares), not a generic request. The digest is byte-identical to the contract's
meta-tx digest, so one keyper signature is verified the same way by every
backend: the in-memory/database stores recover the signer and check committee
membership; the blockchain store relays the signature to the ``...Signed``
contract method, which ``ecrecover``s the same digest. This is what makes keypers
backend-agnostic *and* preserves on-chain per-keyper authorship (§5.3).

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
