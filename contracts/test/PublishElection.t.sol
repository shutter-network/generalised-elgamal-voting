// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PublishElection} from "../script/PublishElection.s.sol";
import {Election} from "../src/Election.sol";
import {ElectionRegistry} from "../src/ElectionRegistry.sol";
import {KeyperSet} from "../src/KeyperSet.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

/// @notice End-to-end test of the operator deploy script: env in → generalised
///         election published under the registry-assigned sequential id.
contract PublishElectionScriptTest is Test {
    uint256 private constant DEPLOYER_PK = 0xA11CE;

    function test_scriptPublishesGeneralisedElectionUnderAssignedId() external {
        address admin = vm.addr(DEPLOYER_PK);
        ElectionRegistry registry = new ElectionRegistry(admin);

        address[] memory members = new address[](3);
        members[0] = address(0x1001);
        members[1] = address(0x1002);
        members[2] = address(0x1003);
        KeyperSet keyperSet = new KeyperSet(members, new string[](members.length), 2);

        vm.setEnv("PRIVATE_KEY", vm.toString(DEPLOYER_PK));
        vm.setEnv("REGISTRY", vm.toString(address(registry)));
        vm.setEnv("KEYPER_SET", vm.toString(address(keyperSet)));
        vm.setEnv("VOTING_START", "1000");
        vm.setEnv("VOTING_END", "2000");
        vm.setEnv("NUM_CANDIDATES", "3");
        vm.setEnv("BUDGET", "3");
        vm.setEnv("MODE", "0");
        vm.setEnv("VARIANT", "0");
        vm.setEnv("WEIGHTED", "true");
        vm.setEnv("MAX_WEIGHT", "10");
        vm.setEnv("DUPLICATE_POLICY", "1");
        vm.setEnv("PROTOCOL_VERSION", "geg-v1");
        vm.setEnv("PK_WR", "0xe1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1");
        vm.setEnv("RESULT_PUBLISHER", vm.toString(address(0xA66)));
        vm.setEnv("VOTE_PROXY", vm.toString(address(0x970)));
        vm.setEnv("SELF_SUBMIT_FEE", "0");

        address electionAddr = new PublishElection().run();

        // First election on a fresh registry → assigned id 1.
        assertEq(registry.elections(1), electionAddr);
        Election election = Election(payable(electionAddr));
        assertEq(election.electionId(), 1);
        assertEq(election.budget(), 3);
        assertTrue(election.weighted());
        assertEq(election.maxWeight(), 10);
        assertEq(election.duplicatePolicy(), 1);

        (VotingTypes.ElectionConfigView memory config,) = election.getElection();
        assertEq(config.protocolVersion, "geg-v1");
        assertEq(config.resultPublisher, address(0xA66));
        assertEq(config.voteProxy, address(0x970));
    }
}
