// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Shared types for the generalised threshold-ElGamal voting bulletin board.
/// @dev Extended from the original Munich bulletin board with the generalised
///      protocol fields (mode/variant/weighted/maxWeight/duplicatePolicy/
///      tallyDeadline/protocolVersion) and an admitted-set aggregate, so the chain
///      adapter can satisfy the full ElectionDataLayer port (see geg DESIGN.md §4.1,
///      §7.2). Enum-like fields are uint8 the adapter maps:
///        mode: 0=exact, 1=atMost
///        variant: 0=A, 1=B
///        duplicatePolicy: 0=first-wins, 1=last-wins
///        exclusion reason: 0=INVALID_PROOF 1=INVALID_SIGNATURE 2=INVALID_ATTESTATION
///                          3=DUPLICATE_PSEUDONYM 4=MALFORMED 5=OUT_OF_WINDOW
library VotingTypes {
    struct ElectionParams {
        uint64 votingStart;
        uint64 votingEnd;
        uint64 tallyDeadline;
        uint256 selfSubmitFee;
        uint32 numCandidates;
        uint32 budget;
        uint8 mode;
        uint8 variant;
        bool weighted;
        uint32 maxWeight;
        uint8 duplicatePolicy;
        string protocolVersion;
        // forge-lint: disable-next-line(mixed-case-variable)
        bytes pkWR;
        address tallyAggregator;
        address voteProxy;
    }

    // forge-lint: disable-next-line(pascal-case-struct)
    struct DLEQProof {
        uint256 e;
        uint256 z;
    }

    /// @notice ElGamal ciphertext in G2: (c1, c2), each 96-byte compressed point.
    struct Ciphertext {
        bytes c1;
        bytes c2;
    }

    /// @notice External ballot payload. ``attestation`` carries the full
    ///         ATTESTATION_V1 credential (incl. weight) verbatim; the contract does
    ///         not interpret it (availability only).
    struct Ballot {
        bytes32 pseudonym;
        bytes vk;
        Ciphertext[] ciphertexts;
        bytes zkProof;
        bytes voterSignature;
        bytes wrAttestation;
    }

    /// @notice Stored ballot metadata alongside the user payload.
    struct BallotRecord {
        Ballot ballot;
        uint64 submittedAt;
        address submittedBy;
    }

    // forge-lint: disable-next-line(pascal-case-struct)
    struct DKGResult {
        bytes pkElection;
        bytes[] committeePKs;
    }

    struct ElectionConfigView {
        uint256 electionId;
        uint64 votingStart;
        uint64 votingEnd;
        uint64 tallyDeadline;
        uint256 selfSubmitFee;
        uint32 numCandidates;
        uint32 budget;
        uint8 mode;
        uint8 variant;
        bool weighted;
        uint32 maxWeight;
        uint8 duplicatePolicy;
        string protocolVersion;
        uint64 thresholdN;
        uint64 thresholdT;
        address[] keyperAddresses;
        // forge-lint: disable-next-line(mixed-case-variable)
        bytes pkWR;
        bool cancelled;
        address adminAddr;
        address tallyAggregator;
        address voteProxy;
        // Per-keyper HTTP endpoints, index-aligned with keyperAddresses (from the KeyperSet).
        string[] keyperEndpoints;
    }

    /// @notice One ballot excluded from the aggregate, with a typed reason code.
    struct Exclusion {
        uint256 sequenceNumber;
        uint8 reason;
    }

    /// @notice Aggregate artifact with its published admitted set (DESIGN.md §7.2).
    struct EncryptedTally {
        Ciphertext[] aggregates;
        uint256[] admitted;
        Exclusion[] exclusions;
        uint256 totalAdmittedWeight;
    }

    struct DecryptionShare {
        uint8 keyperIndex;
        uint64 submittedAt;
        bytes[] shares;
        DLEQProof[] proofs;
    }

    struct ElectionResult {
        uint256[] tally;
        uint8[] keyperIndices;
    }
}
