// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ElectionBase} from "./ElectionBase.sol";
import {VotingTypes} from "../VotingTypes.sol";

abstract contract ElectionTally is ElectionBase {
    function publishAggregate(VotingTypes.EncryptedTally calldata aggregate) external onlyRole(TALLY_AGGREGATOR_ROLE) {
        _requireNotCancelled();
        if (!dkgFinalized) revert DKGNotFinalized();
        if (block.timestamp < votingEnd) revert VotingStillOpen(block.timestamp);
        if (aggregate.aggregates.length != numCandidates) revert InvalidAggregatePayload();

        delete encryptedTally.aggregates;
        for (uint256 index = 0; index < aggregate.aggregates.length; index++) {
            _requireG2Point(aggregate.aggregates[index].c1);
            _requireG2Point(aggregate.aggregates[index].c2);
            encryptedTally.aggregates.push(aggregate.aggregates[index]);
        }

        // Admitted set + exclusions + total admitted weight (DESIGN.md §7.2).
        delete encryptedTally.admitted;
        for (uint256 index = 0; index < aggregate.admitted.length; index++) {
            encryptedTally.admitted.push(aggregate.admitted[index]);
        }
        delete encryptedTally.exclusions;
        for (uint256 index = 0; index < aggregate.exclusions.length; index++) {
            encryptedTally.exclusions.push(aggregate.exclusions[index]);
        }
        encryptedTally.totalAdmittedWeight = aggregate.totalAdmittedWeight;

        aggregatePublished = true;
        emit AggregatePublished(electionId);
    }

    function getAggregate() external view returns (VotingTypes.EncryptedTally memory aggregate) {
        if (!aggregatePublished) revert AggregateNotPublished();
        return encryptedTally;
    }

    function publishResult(uint256[] calldata totals, uint8[] calldata keyperIndices)
        external
        onlyRole(TALLY_AGGREGATOR_ROLE)
    {
        _requireNotCancelled();
        if (!dkgFinalized) revert DKGNotFinalized();
        if (block.timestamp < votingEnd) revert VotingStillOpen(block.timestamp);
        if (totals.length != numCandidates || keyperIndices.length == 0) revert InvalidResultPayload();

        resultFinalized = true;
        electionResult.tally = totals;
        electionResult.keyperIndices = keyperIndices;

        emit ResultPublished(totals, keyperIndices);
    }

    function getResult() external view returns (VotingTypes.ElectionResult memory result) {
        return electionResult;
    }
}
