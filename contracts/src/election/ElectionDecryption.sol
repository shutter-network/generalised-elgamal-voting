// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ElectionBase} from "./ElectionBase.sol";
import {VotingTypes} from "../VotingTypes.sol";

abstract contract ElectionDecryption is ElectionBase {
    /// @notice Decryption share authorized by ``msg.sender``.
    function submitDecryptionShare(bytes[] calldata shares, VotingTypes.DLEQProof[] calldata proofs) external {
        _requireNotCancelled();
        if (!dkgFinalized) revert DKGNotFinalized();
        if (block.timestamp < votingEnd) revert VotingStillOpen(block.timestamp);
        _registerDecryptionShare(msg.sender, shares, proofs);
    }

    /// @notice Decryption share authorized by an embedded keyper signature (meta-tx).
    /// @dev Relayed by the data-layer service; attributed on-chain to the
    ///      ``ecrecover``ed keyper. Signature is EIP-191 over
    ///      ``keccak256("GEG-DECRYPT-SHARE-v1" ‖ electionId ‖ abi.encode(shares) ‖ abi.encode(proofs))``.
    function submitDecryptionShareSigned(
        bytes[] calldata shares, VotingTypes.DLEQProof[] calldata proofs, bytes calldata keyperSig
    ) external {
        _requireNotCancelled();
        if (!dkgFinalized) revert DKGNotFinalized();
        if (block.timestamp < votingEnd) revert VotingStillOpen(block.timestamp);
        bytes32 digest =
            keccak256(abi.encodePacked("GEG-DECRYPT-SHARE-v1", electionId, abi.encode(shares), abi.encode(proofs)));
        address signer = ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(digest), keyperSig);
        _registerDecryptionShare(signer, shares, proofs);
    }

    function _registerDecryptionShare(address voter, bytes[] calldata shares, VotingTypes.DLEQProof[] calldata proofs)
        private
    {
        if (!keyperSet.isMember(voter)) revert UnauthorizedKeyper(voter);
        if (hasSubmittedDecryptionShare[voter]) revert AlreadyVoted(voter);
        if (shares.length != numCandidates || proofs.length != shares.length) {
            revert InvalidDecryptionSharePayload();
        }

        hasSubmittedDecryptionShare[voter] = true;
        decryptionShares.push();
        VotingTypes.DecryptionShare storage share = decryptionShares[decryptionShares.length - 1];
        // forge-lint: disable-next-line(unsafe-typecast)
        share.keyperIndex = uint8(keyperSet.getMemberIndex(voter));
        share.submittedAt = uint64(block.timestamp);

        for (uint256 index = 0; index < shares.length; index++) {
            _requireG2Point(shares[index]);
            share.shares.push(shares[index]);
            share.proofs.push(proofs[index]);
        }

        emit DecryptionSharePosted(share.keyperIndex);
    }

    function getDecryptionShares() external view returns (VotingTypes.DecryptionShare[] memory shares) {
        shares = new VotingTypes.DecryptionShare[](decryptionShares.length);
        for (uint256 index = 0; index < decryptionShares.length; index++) {
            shares[index] = decryptionShares[index];
        }
    }
}
