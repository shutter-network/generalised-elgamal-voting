// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ElectionBase} from "./ElectionBase.sol";

abstract contract ElectionAdmin is ElectionBase {
    /// @notice Cancel the election. Admin-only, permitted strictly before votingStart.
    function cancelElection() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (cancelled) revert AlreadyCancelled();
        if (block.timestamp >= votingStart) revert VotingAlreadyStarted(block.timestamp);
        cancelled = true;
        emit ElectionCancelled(electionId);
    }

    function withdrawFees(address payable recipient) external onlyRole(DEFAULT_ADMIN_ROLE) returns (uint256 amount) {
        if (recipient == address(0)) revert InvalidConfig();
        amount = address(this).balance;
        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert EtherTransferFailed();
        emit FeesWithdrawn(recipient, amount);
    }

    receive() external payable {
        revert DirectETHUnsupported();
    }

    fallback() external payable {
        revert DirectETHUnsupported();
    }
}
