// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {KeyperSet} from "../src/KeyperSet.sol";
import {ElectionRegistry} from "../src/ElectionRegistry.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

contract ScaffoldTest is Test {
    function test_scaffold_deploys() external {
        KeyperSet keyperSet = new KeyperSet(_members(), new string[](_members().length), 2);
        ElectionRegistry registry = new ElectionRegistry(address(this));

        address election = registry.publishElection(keyperSet, _params());
        assertTrue(election != address(0));
        assertEq(registry.electionCount(), 1);
        assertEq(registry.elections(1), election);
    }

    function _params() private pure returns (VotingTypes.ElectionParams memory) {
        return VotingTypes.ElectionParams({
            tallyDeadline: type(uint64).max, mode: 0, variant: 0, weighted: false, maxWeight: 1, duplicatePolicy: 1, protocolVersion: "v1",
            votingStart: 100,
            votingEnd: 200,
            selfSubmitFee: 0.01 ether,
            numCandidates: 3,
            budget: 1,
            pkWR: bytes(""),
            tallyAggregator: address(0xA66),
            voteProxy: address(0x970)
        });
    }

    function _members() private pure returns (address[] memory members) {
        members = new address[](2);
        members[0] = address(0x1001);
        members[1] = address(0x1002);
    }
}
