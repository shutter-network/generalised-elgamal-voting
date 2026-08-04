// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Election} from "../src/Election.sol";
import {ElectionBase} from "../src/election/ElectionBase.sol";
import {IElection} from "../src/interfaces/IElection.sol";
import {KeyperSet} from "../src/KeyperSet.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

contract RejectETH {
    receive() external payable {
        revert("no eth");
    }
}

contract ElectionAdminTest is Test {
    Election private election;
    KeyperSet private keyperSet;

    address private owner = address(0xA11CE);
    address private voter = address(0xCA57);
    address payable private treasury = payable(address(0x777));
    address private voteProxy = address(0x970);
    address private resultPublisher = address(0xA66);
    address private keyper1 = address(0x1001);
    address private keyper2 = address(0x1002);
    address private keyper3 = address(0x1003);
    address private outsider = address(0xBAD);

    uint64 private votingStart = 100;
    uint64 private votingEnd = 200;
    uint256 private selfSubmitFee = 0.01 ether;

    function setUp() external {
        address[] memory members = new address[](3);
        members[0] = keyper1;
        members[1] = keyper2;
        members[2] = keyper3;

        keyperSet = new KeyperSet(members, new string[](members.length), 2);
        election = new Election(owner, 1, keyperSet, _params());

        _finalizeDkg();
        vm.deal(voter, 1 ether);
    }

    function test_withdrawFeesTransfersBalanceToRecipient() external {
        _submitVote(_pseudonym("pseudo-1"));
        _submitVote(_pseudonym("pseudo-2"));
        _finalizeResult();

        uint256 initialTreasuryBalance = treasury.balance;
        uint256 expectedAmount = selfSubmitFee * 2;
        assertEq(address(election).balance, expectedAmount);

        vm.expectEmit(true, false, false, true, address(election));
        emit IElection.FeesWithdrawn(treasury, expectedAmount);

        vm.prank(owner);
        uint256 amount = election.withdrawFees(treasury);

        assertEq(amount, expectedAmount);
        assertEq(address(election).balance, 0);
        assertEq(treasury.balance, initialTreasuryBalance + expectedAmount);
    }

    function test_withdrawFeesRequiresAdmin() external {
        _submitVote(_pseudonym("pseudo-1"));
        _finalizeResult();

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, outsider, election.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(outsider);
        election.withdrawFees(treasury);
    }

    function test_withdrawFeesRejectsInvalidOrFailingRecipient() external {
        _submitVote(_pseudonym("pseudo-1"));
        _finalizeResult();

        vm.prank(owner);
        vm.expectRevert(ElectionBase.InvalidConfig.selector);
        election.withdrawFees(payable(address(0)));

        RejectETH rejectEth = new RejectETH();

        vm.prank(owner);
        vm.expectRevert(ElectionBase.EtherTransferFailed.selector);
        election.withdrawFees(payable(address(rejectEth)));
    }

    function test_withdrawFeesTransfersBeforeResultFinalization() external {
        _submitVote(_pseudonym("pseudo-1"));

        vm.prank(owner);
        uint256 amount = election.withdrawFees(treasury);

        assertEq(amount, selfSubmitFee);
        assertEq(address(election).balance, 0);
    }

    function test_directETHTransfersRevert() external {
        vm.deal(voter, 1 ether);

        vm.prank(voter);
        (bool receiveOk,) = address(election).call{value: 1 wei}("");
        assertFalse(receiveOk);

        vm.prank(voter);
        (bool fallbackOk,) = address(election).call{value: 1 wei}(hex"deadbeef");
        assertFalse(fallbackOk);
    }

    function _submitVote(bytes32 pseudonym) private {
        vm.warp(votingStart);
        vm.prank(voter);
        election.submitVote{value: selfSubmitFee}(_ballot(pseudonym, 10));
    }

    function _pseudonym(string memory label) private pure returns (bytes32) {
        return keccak256(bytes(label));
    }

    function _finalizeDkg() private {
        bytes memory pkElection = _g2Point(1);
        bytes[] memory committeePKs = _committeePKs(20);

        vm.prank(keyper1);
        election.voteDKGResult(pkElection, committeePKs);

        vm.prank(keyper2);
        election.voteDKGResult(pkElection, committeePKs);
    }

    function _finalizeResult() private {
        uint256[] memory totals = new uint256[](3);
        totals[0] = 1;
        totals[1] = 0;
        totals[2] = 0;

        uint8[] memory keyperIndices = new uint8[](2);
        keyperIndices[0] = 0;
        keyperIndices[1] = 1;

        vm.warp(votingEnd);
        vm.prank(resultPublisher);
        election.publishResult(totals, keyperIndices);
    }

    function _ballot(bytes32 pseudonym, uint8 seed) private pure returns (VotingTypes.Ballot memory ballot) {
        ballot.pseudonym = pseudonym;
        ballot.vk = _g1Point(seed);
        ballot.ciphertexts = _ciphertexts(seed);
        ballot.zkProof = abi.encodePacked(seed, seed + 1, seed + 2);
        ballot.voterSignature = abi.encodePacked(bytes32(uint256(seed + 100)));
        ballot.wrAttestation = abi.encodePacked(bytes32(uint256(seed + 200)));
    }

    function _ciphertexts(uint8 seed) private pure returns (VotingTypes.Ciphertext[] memory ciphertexts) {
        ciphertexts = new VotingTypes.Ciphertext[](3);
        ciphertexts[0] = VotingTypes.Ciphertext({c1: _g2Point(seed), c2: _g2Point(seed + 1)});
        ciphertexts[1] = VotingTypes.Ciphertext({c1: _g2Point(seed + 2), c2: _g2Point(seed + 3)});
        ciphertexts[2] = VotingTypes.Ciphertext({c1: _g2Point(seed + 4), c2: _g2Point(seed + 5)});
    }

    function _committeePKs(uint8 seed) private pure returns (bytes[] memory committeePKs) {
        committeePKs = new bytes[](3);
        committeePKs[0] = _g2Point(seed);
        committeePKs[1] = _g2Point(seed + 1);
        committeePKs[2] = _g2Point(seed + 2);
    }

    function _g1Point(uint8 seed) private pure returns (bytes memory point) {
        point = new bytes(48);
        for (uint256 index = 0; index < point.length; index++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            point[index] = bytes1(seed + uint8(index));
        }
    }

    function _g2Point(uint8 seed) private pure returns (bytes memory point) {
        point = new bytes(96);
        for (uint256 index = 0; index < point.length; index++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            point[index] = bytes1(seed + uint8(index));
        }
    }

    function _params() private view returns (VotingTypes.ElectionParams memory) {
        return VotingTypes.ElectionParams({
            mode: 0, variant: 0, weighted: false, maxWeight: 1, duplicatePolicy: 1, protocolVersion: "v1",
            votingStart: votingStart,
            votingEnd: votingEnd,
            selfSubmitFee: selfSubmitFee,
            numCandidates: 3,
            budget: 1,
            pkWR: bytes(""),
            resultPublisher: resultPublisher,
            voteProxy: voteProxy
        });
    }
}
