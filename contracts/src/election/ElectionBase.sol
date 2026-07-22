// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IElection} from "../interfaces/IElection.sol";
import {IKeyperSet} from "../interfaces/IKeyperSet.sol";
import {VotingTypes} from "../VotingTypes.sol";

abstract contract ElectionBase is AccessControl, IElection {
    error AggregateNotPublished();
    error AlreadyFinalized();
    error AlreadyVoted(address keyper);
    error AlreadyCancelled();
    error BallotNotFound(bytes32 pseudonym);
    error InvalidCommitteeLength(uint256 actualLength, uint256 expectedLength);
    error InvalidConfig();
    error InvalidG1PointLength(uint256 actualLength);
    error InvalidG2PointLength(uint256 actualLength);
    error InvalidPseudonym();
    error InvalidResultPayload();
    error InvalidVoteFee(uint256 expectedFee, uint256 actualFee);
    error InvalidVotePayload();
    error InvalidAggregatePayload();
    error InvalidDecryptionSharePayload();
    error DKGNotFinalized();
    error EtherTransferFailed();
    error DirectETHUnsupported();
    error VotingClosed(uint256 timestamp);
    error VotingNotStarted(uint256 timestamp);
    error VotingStillOpen(uint256 timestamp);
    error VotingAlreadyStarted(uint256 timestamp);
    error UnauthorizedKeyper(address account);

    bytes32 public constant VOTE_PROXY_ROLE = keccak256("VOTE_PROXY_ROLE");
    bytes32 public constant TALLY_AGGREGATOR_ROLE = keccak256("TALLY_AGGREGATOR_ROLE");

    uint256 internal constant G2_COMPRESSED_LENGTH = 96;

    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint256 public immutable electionId;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    IKeyperSet public immutable keyperSet;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint64 public immutable votingStart;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint64 public immutable votingEnd;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint64 public immutable tallyDeadline;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint256 public immutable selfSubmitFee;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint32 public immutable numCandidates;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint32 public immutable budget;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint8 public immutable mode;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint8 public immutable variant;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    bool public immutable weighted;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint32 public immutable maxWeight;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint8 public immutable duplicatePolicy;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    address public immutable adminAddr;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    address public immutable tallyAggregatorAddr;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    address public immutable voteProxyAddr;

    string internal protocolVersion;

    bytes internal wrPublicKey;
    bool internal cancelled;
    bool internal dkgFinalized;
    bytes internal electionPublicKey;
    bytes[] internal committeePublicKeys;
    VotingTypes.BallotRecord[] internal ballotRecords;
    mapping(bytes32 => uint256) internal ballotIndexPlusOneByPseudonym;
    VotingTypes.EncryptedTally internal encryptedTally;
    bool internal aggregatePublished;
    VotingTypes.DecryptionShare[] internal decryptionShares;
    bool internal resultFinalized;
    VotingTypes.ElectionResult internal electionResult;

    // forge-lint: disable-next-line(mixed-case-variable)
    mapping(address => bool) internal hasVotedForDKG;
    mapping(bytes32 => uint64) internal dkgVoteCountByResult;
    mapping(address => bool) internal hasSubmittedDecryptionShare;

    constructor(address admin, uint256 electionId_, IKeyperSet keyperSet_, VotingTypes.ElectionParams memory params) {
        if (
            admin == address(0) || address(keyperSet_) == address(0) || params.tallyAggregator == address(0)
                || params.voteProxy == address(0) || params.votingEnd <= params.votingStart || params.numCandidates == 0
                || params.budget == 0 || params.tallyDeadline < params.votingEnd || params.maxWeight == 0
                || (!params.weighted && params.maxWeight != 1)
        ) {
            revert InvalidConfig();
        }

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(TALLY_AGGREGATOR_ROLE, params.tallyAggregator);
        _grantRole(VOTE_PROXY_ROLE, params.voteProxy);

        electionId = electionId_;
        keyperSet = keyperSet_;
        votingStart = params.votingStart;
        votingEnd = params.votingEnd;
        tallyDeadline = params.tallyDeadline;
        selfSubmitFee = params.selfSubmitFee;
        numCandidates = params.numCandidates;
        budget = params.budget;
        mode = params.mode;
        variant = params.variant;
        weighted = params.weighted;
        maxWeight = params.maxWeight;
        duplicatePolicy = params.duplicatePolicy;
        adminAddr = admin;
        tallyAggregatorAddr = params.tallyAggregator;
        voteProxyAddr = params.voteProxy;
        protocolVersion = params.protocolVersion;
        wrPublicKey = params.pkWR;
    }

    // forge-lint: disable-next-line(mixed-case-function)
    function isDKGFinalized() external view returns (bool) {
        return dkgFinalized;
    }

    function isResultFinalized() external view returns (bool) {
        return resultFinalized;
    }

    function isCancelled() external view returns (bool) {
        return cancelled;
    }

    function getPhase() external view returns (uint8 phase) {
        if (block.timestamp >= votingEnd) return 4;
        if (block.timestamp >= votingStart) return 3;
        if (dkgFinalized) return 2;
        return 0;
    }

    function getElection()
        external
        view
        returns (VotingTypes.ElectionConfigView memory config, VotingTypes.DKGResult memory dkgResult)
    {
        config.electionId = electionId;
        config.votingStart = votingStart;
        config.votingEnd = votingEnd;
        config.tallyDeadline = tallyDeadline;
        config.selfSubmitFee = selfSubmitFee;
        config.numCandidates = numCandidates;
        config.budget = budget;
        config.mode = mode;
        config.variant = variant;
        config.weighted = weighted;
        config.maxWeight = maxWeight;
        config.duplicatePolicy = duplicatePolicy;
        config.protocolVersion = protocolVersion;
        config.thresholdN = keyperSet.getNumMembers();
        config.thresholdT = keyperSet.getThreshold();
        config.keyperAddresses = keyperSet.getMembers();
        config.keyperEndpoints = keyperSet.getEndpoints();
        config.pkWR = wrPublicKey;
        config.cancelled = cancelled;
        config.adminAddr = adminAddr;
        config.tallyAggregator = tallyAggregatorAddr;
        config.voteProxy = voteProxyAddr;

        dkgResult.pkElection = electionPublicKey;
        dkgResult.committeePKs = committeePublicKeys;
    }

    function _requireG2Point(bytes memory point) internal pure {
        if (point.length != G2_COMPRESSED_LENGTH) revert InvalidG2PointLength(point.length);
    }

    function _requireNotCancelled() internal view {
        if (cancelled) revert AlreadyCancelled();
    }
}
