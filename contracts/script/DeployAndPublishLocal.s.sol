// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {Election} from "../src/Election.sol";
import {KeyperSet} from "../src/KeyperSet.sol";
import {ElectionRegistry} from "../src/ElectionRegistry.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

/// @notice Low-friction local bootstrap: deploy + publish one default election.
contract DeployAndPublishLocalScript is Script {
    function run() external returns (KeyperSet keyperSet, ElectionRegistry registry, Election election) {
        address admin = vm.envOr("VOTE_MANAGER", msg.sender);
        address[] memory keypers = _keypers(admin);

        vm.startBroadcast();
        keyperSet = new KeyperSet(keypers, new string[](keypers.length), 2);
        registry = new ElectionRegistry(admin);

        address electionAddress = registry.publishElection(keyperSet, _params(admin));
        election = Election(payable(electionAddress));
        vm.stopBroadcast();
    }

    function _keypers(address admin) private view returns (address[] memory keypers) {
        keypers = new address[](2);
        keypers[0] = vm.envOr("KEYPER_1", admin);
        keypers[1] = vm.envOr("KEYPER_2", admin);
    }

    function _params(address admin) private view returns (VotingTypes.ElectionParams memory) {
        return VotingTypes.ElectionParams({
            mode: 0, variant: 0, weighted: false, maxWeight: 1, duplicatePolicy: 1, protocolVersion: "v1",
            votingStart: uint64(vm.envOr("VOTING_START", uint256(block.timestamp + 1 hours))),
            votingEnd: uint64(vm.envOr("VOTING_END", uint256(block.timestamp + 25 hours))),
            selfSubmitFee: vm.envOr("SELF_SUBMIT_FEE", uint256(0.01 ether)),
            numCandidates: uint32(vm.envOr("NUM_CANDIDATES", uint256(3))),
            budget: uint32(vm.envOr("BUDGET", uint256(1))),
            pkWR: vm.envOr("PK_WR", bytes("")),
            resultPublisher: vm.envOr("RESULT_PUBLISHER", admin),
            voteProxy: vm.envOr("VOTE_PROXY", admin)
        });
    }
}
