// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Election} from "./Election.sol";
import {IElectionRegistry} from "./interfaces/IElectionRegistry.sol";
import {IKeyperSet} from "./interfaces/IKeyperSet.sol";
import {VotingTypes} from "./VotingTypes.sol";

/// @notice Admin-gated factory + index of Election instances (scaffold only).
contract ElectionRegistry is AccessControl, IElectionRegistry {
    error InvalidKeyperSet();

    bytes32 public constant VOTE_PROXY_ROLE = keccak256("VOTE_PROXY_ROLE");
    bytes32 public constant TALLY_AGGREGATOR_ROLE = keccak256("TALLY_AGGREGATOR_ROLE");

    uint256 public electionCount;
    mapping(uint256 => address) public elections;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Publish an election under the next sequential id (DESIGN.md §4.1).
    /// @dev electionId is assigned by the registry (++electionCount), matching the
    ///      canonical bulletin-board model — ids are dense and enumerable, and no
    ///      caller-chosen id is accepted.
    function publishElection(IKeyperSet keyperSet, VotingTypes.ElectionParams calldata params)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
        returns (address electionAddr)
    {
        return _publishElection(msg.sender, keyperSet, params);
    }

    function _publishElection(address admin, IKeyperSet keyperSet, VotingTypes.ElectionParams calldata params)
        private
        returns (address electionAddr)
    {
        uint64 numMembers = keyperSet.getNumMembers();
        uint64 threshold = keyperSet.getThreshold();
        if (numMembers == 0 || threshold == 0 || threshold > numMembers) {
            revert InvalidKeyperSet();
        }

        uint256 electionId = ++electionCount;
        Election election = new Election(admin, electionId, keyperSet, params);
        electionAddr = address(election);
        elections[electionId] = electionAddr;
        emit ElectionCreated(electionAddr, electionId, address(keyperSet));
    }

    function getElections(uint256 startElectionId, uint256 count) external view returns (address[] memory result) {
        result = new address[](count);
        for (uint256 index = 0; index < count; index++) {
            result[index] = elections[startElectionId + index];
        }
    }
}
