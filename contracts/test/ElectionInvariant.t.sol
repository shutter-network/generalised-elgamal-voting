// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Election} from "../src/Election.sol";
import {KeyperSet} from "../src/KeyperSet.sol";
import {VotingTypes} from "../src/VotingTypes.sol";

contract ElectionHandler is Test {
    Election public election;

    address private owner = address(0xA11CE);
    address private voter1 = address(0xCA57);
    address private voter2 = address(0xCA58);
    address private voteProxy = address(0x970);
    address private resultPublisher = address(0xA66);
    address private keyper1 = address(0x1001);
    address private keyper2 = address(0x1002);
    address private keyper3 = address(0x1003);

    uint64 private votingStart = 100;
    uint64 private votingEnd = 200;
    uint256 private selfSubmitFee = 0.01 ether;

    uint256 public expectedBallots;
    uint256 public expectedShares;
    uint256 public expectedFees;

    constructor() {
        address[] memory members = new address[](3);
        members[0] = keyper1;
        members[1] = keyper2;
        members[2] = keyper3;

        KeyperSet keyperSet = new KeyperSet(members, new string[](members.length), 2);
        election = new Election(owner, 1, keyperSet, _params());

        _finalizeDkg();
    }

    function submitSelfVote(uint8 voterSeed, bytes32 pseudonymSeed) external {
        address voter = voterSeed % 2 == 0 ? voter1 : voter2;
        vm.deal(voter, 100 ether);
        vm.warp(votingStart);
        vm.prank(voter);

        try election.submitVote{value: selfSubmitFee}(_ballot(pseudonymSeed, uint8(10 + voterSeed % 100))) {
            expectedBallots++;
            expectedFees += selfSubmitFee;
        } catch {}
    }

    function submitProxyVote(bytes32 pseudonymSeed) external {
        vm.warp(votingStart);
        vm.prank(voteProxy);

        try election.submitVote(_ballot(pseudonymSeed, 40)) {
            expectedBallots++;
        } catch {}
    }

    function submitShare(uint8 keyperSeed) external {
        address keyper = _keyper(keyperSeed);
        vm.warp(votingEnd);
        vm.prank(keyper);

        try election.submitDecryptionShare(_shares(uint8(80 + keyperSeed % 50)), _proofs(11 + keyperSeed % 10)) {
            expectedShares++;
        } catch {}
    }

    function finalizeResult() external {
        uint256[] memory totals = new uint256[](3);
        totals[0] = expectedBallots;

        uint8[] memory keyperIndices = new uint8[](2);
        keyperIndices[0] = 0;
        keyperIndices[1] = 1;

        vm.warp(votingEnd);
        vm.prank(resultPublisher);
        try election.publishResult(totals, keyperIndices) {} catch {}
    }

    function _keyper(uint8 keyperSeed) private view returns (address) {
        if (keyperSeed % 3 == 0) return keyper1;
        if (keyperSeed % 3 == 1) return keyper2;
        return keyper3;
    }

    function _finalizeDkg() private {
        bytes memory pkElection = _g2Point(1);
        bytes[] memory committeePKs = _committeePKs(20);

        vm.prank(keyper1);
        election.voteDKGResult(pkElection, committeePKs);

        vm.prank(keyper2);
        election.voteDKGResult(pkElection, committeePKs);
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

    function _shares(uint8 seed) private pure returns (bytes[] memory shares) {
        shares = new bytes[](3);
        shares[0] = _g2Point(seed);
        shares[1] = _g2Point(seed + 1);
        shares[2] = _g2Point(seed + 2);
    }

    function _proofs(uint256 seed) private pure returns (VotingTypes.DLEQProof[] memory proofs) {
        proofs = new VotingTypes.DLEQProof[](3);
        proofs[0] = VotingTypes.DLEQProof({e: seed, z: seed + 1});
        proofs[1] = VotingTypes.DLEQProof({e: seed + 2, z: seed + 3});
        proofs[2] = VotingTypes.DLEQProof({e: seed + 4, z: seed + 5});
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
            tallyDeadline: type(uint64).max, mode: 0, variant: 0, weighted: false, maxWeight: 1, duplicatePolicy: 1, protocolVersion: "v1",
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

contract ElectionInvariantTest is Test {
    ElectionHandler private handler;
    Election private election;

    function setUp() external {
        handler = new ElectionHandler();
        election = handler.election();
        targetContract(address(handler));
    }

    function invariant_ballotCountMatchesSuccessfulSubmissions() external view {
        assertEq(election.getNumBallots(), handler.expectedBallots());
    }

    function invariant_decryptionShareCountMatchesSuccessfulSubmissions() external view {
        assertEq(election.getDecryptionShares().length, handler.expectedShares());
    }

    function invariant_feeBalanceMatchesSelfSubmittedVotes() external view {
        assertEq(address(election).balance, handler.expectedFees());
    }
}
