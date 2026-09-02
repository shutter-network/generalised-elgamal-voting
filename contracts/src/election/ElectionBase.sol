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
    bytes32 public constant RESULT_PUBLISHER_ROLE = keccak256("RESULT_PUBLISHER_ROLE");

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
    uint32 public immutable scale;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint8 public immutable duplicatePolicy;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    address public immutable adminAddr;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    address public immutable resultPublisherAddr;
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
    // Canonical aggregate stored as its ABI-encoded blob (set once at the t+1 quorum);
    // decoded on read. Cheaper bytecode than structured storage — matters for EIP-170.
    bytes internal encryptedTallyEncoded;
    bool internal aggregatePublished;
    VotingTypes.DecryptionShare[] internal decryptionShares;
    bool internal resultFinalized;
    // Advisory, recoverable: the off-chain coordinator abandoned the tally after exhausting
    // its attempts (too few keypers for the quorum). Public getter for the data-layer adapter;
    // set/cleared by the result publisher. Not a protocol gate — a published result wins.
    bool public tallyStalled;
    VotingTypes.ElectionResult internal electionResult;

    // forge-lint: disable-next-line(mixed-case-variable)
    mapping(address => bool) internal hasVotedForDKG;
    mapping(bytes32 => uint64) internal dkgVoteCountByResult;
    // Aggregate votes are mutable until the quorum finalizes: track each keyper's
    // current digest (0 = not yet voted) so an override moves its vote between digests.
    mapping(address => bytes32) internal aggregateVoteDigestOf;
    mapping(bytes32 => uint64) internal aggregateVoteCountByResult;
    mapping(address => bool) internal hasSubmittedDecryptionShare;

    constructor(address admin, uint256 electionId_, IKeyperSet keyperSet_, VotingTypes.ElectionParams memory params) {
        if (
            admin == address(0) || address(keyperSet_) == address(0) || params.resultPublisher == address(0)
                || params.voteProxy == address(0) || params.votingEnd <= params.votingStart || params.numCandidates == 0
                || params.budget == 0 || params.scale == 0
        ) {
            revert InvalidConfig();
        }

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RESULT_PUBLISHER_ROLE, params.resultPublisher);
        _grantRole(VOTE_PROXY_ROLE, params.voteProxy);

        electionId = electionId_;
        keyperSet = keyperSet_;
        votingStart = params.votingStart;
        votingEnd = params.votingEnd;
        selfSubmitFee = params.selfSubmitFee;
        numCandidates = params.numCandidates;
        budget = params.budget;
        mode = params.mode;
        variant = params.variant;
        weighted = params.weighted;
        scale = params.scale;
        duplicatePolicy = params.duplicatePolicy;
        adminAddr = admin;
        resultPublisherAddr = params.resultPublisher;
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
        config.selfSubmitFee = selfSubmitFee;
        config.numCandidates = numCandidates;
        config.budget = budget;
        config.mode = mode;
        config.variant = variant;
        config.weighted = weighted;
        config.scale = scale;
        config.duplicatePolicy = duplicatePolicy;
        config.protocolVersion = protocolVersion;
        config.thresholdN = keyperSet.getNumMembers();
        config.thresholdT = keyperSet.getThreshold();
        config.keyperAddresses = keyperSet.getMembers();
        config.keyperURLs = keyperSet.getURLs();
        config.pkWR = wrPublicKey;
        config.cancelled = cancelled;
        config.adminAddr = adminAddr;
        config.resultPublisher = resultPublisherAddr;
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
