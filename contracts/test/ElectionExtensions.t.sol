// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Election} from "../src/Election.sol";
import {ElectionBase} from "../src/election/ElectionBase.sol";
import {IElection} from "../src/interfaces/IElection.sol";
import {KeyperSet} from "../src/KeyperSet.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

/// @notice Tests for the generalised extensions: cancellation + admitted-set aggregate.
contract ElectionExtensionsTest is Test {
    Election private election;
    KeyperSet private keyperSet;

    address private owner = address(0xA11CE);
    address private voteProxy = address(0x970);
    address private resultPublisher = address(0xA66);
    address private keyper1 = address(0x1001);
    address private keyper2 = address(0x1002);
    address private keyper3 = address(0x1003);
    address private outsider = address(0xBAD);

    uint64 private votingStart = 100;
    uint64 private votingEnd = 200;

    function setUp() external {
        address[] memory members = new address[](3);
        members[0] = keyper1;
        members[1] = keyper2;
        members[2] = keyper3;
        keyperSet = new KeyperSet(members, new string[](members.length), 2);
        election = new Election(owner, 1, keyperSet, _params());
    }

    // -- cancellation ------------------------------------------------------- #

    function test_adminCancelsBeforeStart() external {
        vm.warp(50);
        vm.expectEmit(true, false, false, false, address(election));
        emit IElection.ElectionCancelled(1);
        vm.prank(owner);
        election.cancelElection();

        assertTrue(election.isCancelled());
        (VotingTypes.ElectionConfigView memory config,) = election.getElection();
        assertTrue(config.cancelled);
    }

    function test_cancelRejectedAtOrAfterStart() external {
        vm.warp(votingStart);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ElectionBase.VotingAlreadyStarted.selector, votingStart));
        election.cancelElection();
    }

    function test_cancelOnlyAdmin() external {
        vm.warp(50);
        vm.prank(outsider);
        vm.expectRevert();
        election.cancelElection();
    }

    function test_cancelBlocksDkg() external {
        vm.warp(50);
        vm.prank(owner);
        election.cancelElection();

        vm.prank(keyper1);
        vm.expectRevert(ElectionBase.AlreadyCancelled.selector);
        election.voteDKGResult(_g2Point(1), _committeePKs(10));
    }

    function test_doubleCancelReverts() external {
        vm.warp(50);
        vm.startPrank(owner);
        election.cancelElection();
        vm.expectRevert(ElectionBase.AlreadyCancelled.selector);
        election.cancelElection();
        vm.stopPrank();
    }

    // -- admitted-set aggregate --------------------------------------------- #

    function test_submitAggregateStoresAdmittedSetAtQuorum() external {
        _finalizeDkg();
        vm.warp(votingEnd);

        VotingTypes.EncryptedTally memory agg;
        agg.aggregates = _ciphertexts(70);
        agg.admitted = new uint256[](2);
        agg.admitted[0] = 0;
        agg.admitted[1] = 2;
        agg.exclusions = new VotingTypes.Exclusion[](1);
        agg.exclusions[0] = VotingTypes.Exclusion({sequenceNumber: 1, reason: 3}); // DUPLICATE_PSEUDONYM
        agg.totalAdmittedWeight = 5;

        // Committee-owned aggregation: canonical only at the t+1 byte-identical quorum,
        // and the full admitted set / exclusions / weight survive the quorum store.
        vm.prank(keyper1);
        election.submitAggregate(agg);
        vm.prank(keyper2);
        election.submitAggregate(agg);

        VotingTypes.EncryptedTally memory stored = election.getAggregate();
        assertEq(stored.aggregates.length, 3);
        assertEq(stored.admitted.length, 2);
        assertEq(stored.admitted[1], 2);
        assertEq(stored.exclusions.length, 1);
        assertEq(stored.exclusions[0].sequenceNumber, 1);
        assertEq(stored.exclusions[0].reason, 3);
        assertEq(stored.totalAdmittedWeight, 5);
    }

    function test_tallyDeadlineExposedInConfig() external view {
        (VotingTypes.ElectionConfigView memory config,) = election.getElection();
        assertEq(config.tallyDeadline, type(uint64).max);
        assertEq(config.protocolVersion, "v1");
        assertEq(config.duplicatePolicy, 1);
    }

    // -- helpers ------------------------------------------------------------ #

    function _finalizeDkg() private {
        bytes memory pk = _g2Point(1);
        bytes[] memory committee = _committeePKs(10);
        vm.prank(keyper1);
        election.voteDKGResult(pk, committee);
        vm.prank(keyper2);
        election.voteDKGResult(pk, committee);
        assertTrue(election.isDKGFinalized());
    }

    function _ciphertexts(uint8 seed) private pure returns (VotingTypes.Ciphertext[] memory cts) {
        cts = new VotingTypes.Ciphertext[](3);
        cts[0] = VotingTypes.Ciphertext({c1: _g2Point(seed), c2: _g2Point(seed + 1)});
        cts[1] = VotingTypes.Ciphertext({c1: _g2Point(seed + 2), c2: _g2Point(seed + 3)});
        cts[2] = VotingTypes.Ciphertext({c1: _g2Point(seed + 4), c2: _g2Point(seed + 5)});
    }

    function _committeePKs(uint8 seed) private pure returns (bytes[] memory pks) {
        pks = new bytes[](3);
        pks[0] = _g2Point(seed);
        pks[1] = _g2Point(seed + 1);
        pks[2] = _g2Point(seed + 2);
    }

    function _g2Point(uint8 seed) private pure returns (bytes memory point) {
        point = new bytes(96);
        for (uint256 i = 0; i < point.length; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            point[i] = bytes1(seed + uint8(i));
        }
    }

    function _params() private view returns (VotingTypes.ElectionParams memory) {
        return VotingTypes.ElectionParams({
            votingStart: votingStart,
            votingEnd: votingEnd,
            tallyDeadline: type(uint64).max,
            selfSubmitFee: 0,
            numCandidates: 3,
            budget: 1,
            mode: 0,
            variant: 0,
            weighted: false,
            maxWeight: 1,
            duplicatePolicy: 1,
            protocolVersion: "v1",
            pkWR: bytes(""),
            resultPublisher: resultPublisher,
            voteProxy: voteProxy
        });
    }
}
