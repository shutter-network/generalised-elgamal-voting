// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IKeyperSet} from "./interfaces/IKeyperSet.sol";

error DuplicateMember(address member);
error InvalidMember(address member);
error InvalidThreshold(uint64 threshold, uint256 membersLen);
error URLsLengthMismatch(uint256 urlsLen, uint256 membersLen);

/// @notice Immutable keyper membership, threshold, and per-member HTTP URLs.
/// @dev URLs are operational discovery metadata (where each keyper is reachable
///      for the DKG/decryption ceremony). They are fixed for the committee's lifetime
///      (a fresh KeyperSet is deployed per election), so storing them here — rather
///      than off-chain env — lets any service read them through the data-layer port.
contract KeyperSet is IKeyperSet {
    uint64 private threshold;

    address[] private members;
    string[] private urls;
    mapping(address => uint64) private memberIndexPlusOne;

    constructor(address[] memory initialMembers, string[] memory initialURLs, uint64 initialThreshold) {
        // URLs are REQUIRED and pair with members 1:1 (member i ↔ url i).
        if (initialURLs.length != initialMembers.length) {
            revert URLsLengthMismatch(initialURLs.length, initialMembers.length);
        }
        for (uint256 i = 0; i < initialMembers.length; i++) {
            address member = initialMembers[i];
            if (member == address(0)) revert InvalidMember(member);
            if (memberIndexPlusOne[member] != 0) revert DuplicateMember(member);
            // forge-lint: disable-next-line(unsafe-typecast)
            memberIndexPlusOne[member] = uint64(i + 1);
            members.push(member);
        }

        if (initialThreshold == 0 || initialThreshold > members.length) {
            revert InvalidThreshold(initialThreshold, members.length);
        }
        threshold = initialThreshold;
        urls = initialURLs;
    }

    function getNumMembers() external view returns (uint64) {
        return uint64(members.length);
    }

    function getMember(uint64 index) external view returns (address) {
        return members[index];
    }

    function getMembers() external view returns (address[] memory) {
        return members;
    }

    function getURLs() external view returns (string[] memory) {
        return urls;
    }

    function getMemberIndex(address account) external view returns (uint64) {
        uint64 indexPlusOne = memberIndexPlusOne[account];
        if (indexPlusOne == 0) revert InvalidMember(account);
        return indexPlusOne - 1;
    }

    function getThreshold() external view returns (uint64) {
        return threshold;
    }

    function isMember(address account) external view returns (bool) {
        return memberIndexPlusOne[account] != 0;
    }
}
