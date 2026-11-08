// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatRegistry
 * @notice Decentralized threat intelligence registry for anchoring threat assessment reports.
 *
 * DESIGN RULE: Raw URLs, personal information, and email content remain off-chain.
 * A blockchain record establishes the integrity and provenance of a report,
 * not the truth of the report itself.
 */
contract ThreatRegistry {
    /// @notice Classification codes matching off-chain enum:
    /// 0 = low_risk, 1 = suspicious, 2 = high_risk, 3 = confirmed_malicious, 4 = inconclusive

    struct Commitment {
        bytes32 reportHash;           // SHA-256 of canonical report JSON
        bytes32 targetFingerprint;    // SHA-256 of normalized domain/target (NEVER raw URL/PII)
        uint8 classificationCode;     // 0-4 matching Classification enum
        uint8 score;                  // Risk score 0-100
        uint64 timestamp;             // Unix timestamp
        address reporter;             // Address that anchored the report
    }

    /// @notice Mapping from reportIdHash (keccak256(report_id)) to Commitment
    mapping(bytes32 => Commitment) public commitments;

    /// @notice Emitted when a report is anchored on-chain
    event ReportAnchored(
        bytes32 indexed reportIdHash,
        bytes32 indexed reportHash,
        bytes32 indexed targetFingerprint,
        uint8 classificationCode,
        uint8 score,
        address indexed reporter,
        uint64 timestamp
    );

    /// @notice Anchors a threat assessment report on-chain
    /// @param reportIdHash keccak256(bytes(report_id)) - unique identifier for the report
    /// @param reportHash SHA-256 hash of canonical report JSON
    /// @param targetFingerprint SHA-256 of normalized domain/target (privacy-preserving)
    /// @param classificationCode Classification enum code (0-4)
    /// @param score Risk score 0-100
    function anchorReport(
        bytes32 reportIdHash,
        bytes32 reportHash,
        bytes32 targetFingerprint,
        uint8 classificationCode,
        uint8 score
    ) external {
        require(reportHash != bytes32(0), "Report hash cannot be zero");
        require(targetFingerprint != bytes32(0), "Target fingerprint cannot be zero");
        require(classificationCode <= 4, "Invalid classification code");
        require(score <= 100, "Score must be 0-100");

        Commitment memory commitment = Commitment({
            reportHash: reportHash,
            targetFingerprint: targetFingerprint,
            classificationCode: classificationCode,
            score: score,
            timestamp: uint64(block.timestamp),
            reporter: msg.sender
        });

        commitments[reportIdHash] = commitment;

        emit ReportAnchored(
            reportIdHash,
            reportHash,
            targetFingerprint,
            classificationCode,
            score,
            msg.sender,
            uint64(block.timestamp)
        );
    }

    /// @notice Verifies a report against its on-chain commitment
    /// @param reportIdHash keccak256(bytes(report_id))
    /// @param expectedReportHash The expected SHA-256 report hash to verify against
    /// @return exists Whether a commitment exists for this reportIdHash
    /// @return matches Whether the stored reportHash matches expectedReportHash
    /// @return timestamp Unix timestamp of the anchoring
    /// @return reporter Address that anchored the report
    function verifyReport(
        bytes32 reportIdHash,
        bytes32 expectedReportHash
    ) external view returns (bool exists, bool matches, uint64 timestamp, address reporter) {
        Commitment storage c = commitments[reportIdHash];
        exists = (c.reportHash != bytes32(0));
        matches = exists && (c.reportHash == expectedReportHash);
        timestamp = c.timestamp;
        reporter = c.reporter;
    }
}