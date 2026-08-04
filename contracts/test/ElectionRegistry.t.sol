// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Election} from "../src/Election.sol";
import {ElectionBase} from "../src/election/ElectionBase.sol";
import {ElectionRegistry} from "../src/ElectionRegistry.sol";
import {IKeyperSet} from "../src/interfaces/IKeyperSet.sol";
import {KeyperSet} from "../src/KeyperSet.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

contract MockKeyperSet is IKeyperSet {
    uint64 private numMembers;
    uint64 private threshold;

    constructor(uint64 numMembers_, uint64 threshold_) {
        numMembers = numMembers_;
        threshold = threshold_;
    }

    function getNumMembers() external view returns (uint64) {
        return numMembers;
    }

    function getMember(uint64) external pure returns (address) {
        return address(0);
    }

    function getMembers() external pure returns (address[] memory) {
        return new address[](0);
    }

    function getURLs() external pure returns (string[] memory) {
        return new string[](0);
    }

    function getMemberIndex(address) external pure returns (uint64) {
        return 0;
    }

    function getThreshold() external view returns (uint64) {
        return threshold;
    }

    function isMember(address) external pure returns (bool) {
        return false;
    }
}

contract ElectionRegistryTest is Test {
    ElectionRegistry private registry;
    KeyperSet private keyperSet;

    address private voteManager = address(0xA11CE);
    address private nonAdmin = address(0xBAD);
    address private resultPublisher = address(0xA66);
    address private voteProxy = address(0x970);

    event ElectionCreated(address indexed election, uint256 indexed electionId, address indexed keyperSet);

    function setUp() external {
        registry = new ElectionRegistry(voteManager);
        keyperSet = new KeyperSet(_members(), new string[](_members().length), 2);
    }

    function test_createElectionStoresAddressAndConfiguresElection() external {
        VotingTypes.ElectionParams memory params = _params();

        vm.prank(voteManager);
        address electionAddress = registry.publishElection(keyperSet, params);
        Election election = Election(payable(electionAddress));

        assertEq(registry.electionCount(), 1);
        assertEq(registry.elections(1), electionAddress);
        assertEq(election.electionId(), 1);
        assertEq(address(election.keyperSet()), address(keyperSet));
        assertEq(election.votingStart(), params.votingStart);
        assertEq(election.votingEnd(), params.votingEnd);
        assertEq(election.selfSubmitFee(), params.selfSubmitFee);
        assertEq(election.numCandidates(), params.numCandidates);
        assertEq(election.budget(), params.budget);
        assertTrue(election.hasRole(election.DEFAULT_ADMIN_ROLE(), voteManager));
        assertTrue(election.hasRole(election.RESULT_PUBLISHER_ROLE(), resultPublisher));
        assertTrue(election.hasRole(election.VOTE_PROXY_ROLE(), voteProxy));
    }

    function test_createElectionEmitsEvent() external {
        vm.prank(voteManager);
        vm.expectEmit(false, true, true, false, address(registry));
        emit ElectionCreated(address(0), 1, address(keyperSet));
        registry.publishElection(keyperSet, _params());
    }

    function test_createElectionIncrementsIds() external {
        vm.startPrank(voteManager);
        address firstElection = registry.publishElection(keyperSet, _params());
        address secondElection = registry.publishElection(keyperSet, _params());
        vm.stopPrank();

        assertEq(registry.electionCount(), 2);
        assertEq(registry.elections(1), firstElection);
        assertEq(registry.elections(2), secondElection);
        assertTrue(firstElection != secondElection);
        assertEq(Election(payable(firstElection)).electionId(), 1);
        assertEq(Election(payable(secondElection)).electionId(), 2);

        address[] memory storedElections = registry.getElections(1, 2);
        assertEq(storedElections.length, 2);
        assertEq(storedElections[0], firstElection);
        assertEq(storedElections[1], secondElection);
    }

    function test_createElectionRejectsNonAdmin() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, nonAdmin, registry.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(nonAdmin);
        registry.publishElection(keyperSet, _params());
    }

    function test_createElectionRejectsInvalidConfig() external {
        VotingTypes.ElectionParams memory params = _params();
        params.votingEnd = params.votingStart;

        vm.prank(voteManager);
        vm.expectRevert(ElectionBase.InvalidConfig.selector);
        registry.publishElection(keyperSet, params);
    }

    function test_createElectionRejectsInvalidKeyperSet() external {
        MockKeyperSet emptyKeyperSet = new MockKeyperSet(0, 0);
        MockKeyperSet zeroThresholdKeyperSet = new MockKeyperSet(2, 0);
        MockKeyperSet highThresholdKeyperSet = new MockKeyperSet(2, 3);

        vm.startPrank(voteManager);

        vm.expectRevert(ElectionRegistry.InvalidKeyperSet.selector);
        registry.publishElection(emptyKeyperSet, _params());

        vm.expectRevert(ElectionRegistry.InvalidKeyperSet.selector);
        registry.publishElection(zeroThresholdKeyperSet, _params());

        vm.expectRevert(ElectionRegistry.InvalidKeyperSet.selector);
        registry.publishElection(highThresholdKeyperSet, _params());

        vm.stopPrank();
    }

    function _params() private view returns (VotingTypes.ElectionParams memory) {
        return VotingTypes.ElectionParams({
            mode: 0, variant: 0, weighted: false, maxWeight: 1, duplicatePolicy: 1, protocolVersion: "v1",
            votingStart: 100,
            votingEnd: 200,
            selfSubmitFee: 0.01 ether,
            numCandidates: 3,
            budget: 1,
            pkWR: bytes(""),
            resultPublisher: resultPublisher,
            voteProxy: voteProxy
        });
    }

    function _members() private pure returns (address[] memory members) {
        members = new address[](2);
        members[0] = address(0x1001);
        members[1] = address(0x1002);
    }
}
