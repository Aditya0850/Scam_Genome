"""Tests for trustlens.chain (decentralized threat intelligence & on-chain verification)."""

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from trustlens.chain import anchor_report, verify_on_chain
from trustlens.config import Settings
from trustlens.db import compute_report_hash, save_report
from trustlens.models import Assessment, CheckStatus, Classification, Finding, Severity


def _make_assessment(
    target: str = "https://example.com/",
    classification: Classification = Classification.LOW_RISK,
    score: int = 0,
    findings: list[Finding] | None = None,
    kind: str = "url",
    report_id: str | None = None,
    timestamp: datetime | None = None,
) -> Assessment:
    """Create a test assessment."""
    if findings is None:
        findings = []
    checks = [CheckStatus(check="lexical", ran=True), CheckStatus(check="safefetch", ran=True)]
    kwargs = dict(
        kind=kind,
        target=target,
        classification=classification,
        score=score,
        findings=findings,
        checks=checks,
        coverage=1.0,
        report_id=report_id,
    )
    if timestamp is not None:
        kwargs["timestamp"] = timestamp
    return Assessment(**kwargs)


def _make_finding(
    finding_id: str = "TEST_FINDING",
    severity: Severity = Severity.MEDIUM,
    evidence: str = "test evidence",
    source: str = "test",
    weight: int = 10,
) -> Finding:
    """Create a test finding."""
    return Finding(
        id=finding_id,
        check="test",
        title="Test Finding",
        severity=severity,
        evidence=evidence,
        source=source,
        confidence=0.8,
        weight=weight,
    )


def test_anchor_report_local_ledger_creates_tx_hash() -> None:
    """Anchoring a report in local ledger mode generates valid tx_hash and report_hash."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    settings = Settings(db_path=db_path, rpc_url="", contract_address="", private_key="")

    try:
        assessment = _make_assessment(
            target="https://phish.example.com/login",
            classification=Classification.HIGH_RISK,
            score=75,
            findings=[_make_finding("LEX_TYPOSQUAT", Severity.HIGH, "typosquat", "lexical", 40)],
        )
        # Save to DB first to get report_id
        assessment = save_report(assessment, db_path=db_path)
        assert assessment.report_id is not None
        assert assessment.report_hash is not None

        # Anchor the report
        result = anchor_report(assessment, settings)

        # Verify result structure
        assert "tx_hash" in result
        assert result["tx_hash"].startswith("0x")
        assert len(result["tx_hash"]) == 66  # 0x + 64 hex chars
        assert "report_hash" in result
        assert result["report_hash"] == assessment.report_hash
        assert "target_fingerprint" in result
        assert result["target_fingerprint"].startswith("0x")
        assert len(result["target_fingerprint"]) == 66
        assert result["mode"] == "local_ledger"
        assert "block_number" in result
        assert result["block_number"] == 1

        # Verify assessment was updated with tx_hash
        assert assessment.tx_hash == result["tx_hash"]

        # Verify ledger file exists and contains correct data
        ledger_path = Path(db_path).with_suffix(".chain.json")
        assert ledger_path.exists()

        with open(ledger_path, "r") as f:
            ledger = json.load(f)
        assert len(ledger) == 1
        entry = ledger[0]
        assert entry["report_id"] == assessment.report_id
        assert entry["report_hash"] == assessment.report_hash
        assert entry["tx_hash"] == result["tx_hash"]
        assert entry["target_fingerprint"] == result["target_fingerprint"]
        assert entry["score"] == 75
        assert entry["classification"] == "high_risk"

    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)


def test_anchor_report_target_fingerprint_no_raw_url() -> None:
    """Verify target_fingerprint is SHA-256 of target, not raw URL stored."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    settings = Settings(db_path=db_path, rpc_url="", contract_address="", private_key="")

    try:
        # Test with URL
        assessment = _make_assessment(target="https://evil.com/steal?password=secret")
        assessment = save_report(assessment, db_path=db_path)
        result = anchor_report(assessment, settings)

        # target_fingerprint should be SHA-256 of the target string
        expected_fingerprint = "0x" + hashlib.sha256(b"https://evil.com/steal?password=secret").hexdigest()
        assert result["target_fingerprint"] == expected_fingerprint

        # Verify raw URL does NOT appear in ledger file
        ledger_path = Path(db_path).with_suffix(".chain.json")
        with open(ledger_path, "r") as f:
            ledger_content = f.read()

        assert "evil.com" not in ledger_content
        assert "steal" not in ledger_content
        assert "password" not in ledger_content
        assert "secret" not in ledger_content
        # Only the fingerprint (hash) should be present
        assert expected_fingerprint in ledger_content

    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)


def test_anchor_report_updates_sqlite_tx_hash() -> None:
    """Verify anchoring updates the report's tx_hash in SQLite."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    settings = Settings(db_path=db_path, rpc_url="", contract_address="", private_key="")

    try:
        assessment = _make_assessment(target="https://test.example.com/")
        assessment = save_report(assessment, db_path=db_path)
        original_tx_hash = assessment.tx_hash
        assert original_tx_hash is None

        result = anchor_report(assessment, settings)

        # Reload from DB
        from trustlens.db import get_report

        reloaded = get_report(assessment.report_id, db_path=db_path)
        assert reloaded is not None
        assert reloaded.tx_hash == result["tx_hash"]
        assert reloaded.tx_hash != original_tx_hash

    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)


def test_verify_on_chain_unmodified_report() -> None:
    """Verify returns integrity_verified: True for unmodified anchored report."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    settings = Settings(db_path=db_path, rpc_url="", contract_address="", private_key="")

    try:
        assessment = _make_assessment(
            target="https://verify.example.com/",
            classification=Classification.SUSPICIOUS,
            score=45,
        )
        assessment = save_report(assessment, db_path=db_path)
        anchor_report(assessment, settings)

        # Verify the report
        result = verify_on_chain(assessment.report_id, settings)

        assert result["report_id"] == assessment.report_id
        assert result["stored_hash"] == assessment.report_hash
        assert result["recomputed_hash"] == assessment.report_hash
        assert result["on_chain_hash"] == assessment.report_hash
        assert result["tx_hash"] == assessment.tx_hash
        assert result["anchored"] is True
        assert result["integrity_verified"] is True
        assert "provenance_note" in result

    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)


def test_verify_on_chain_tampered_report() -> None:
    """Verify returns integrity_verified: False if SQLite record tampered after anchoring."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    settings = Settings(db_path=db_path, rpc_url="", contract_address="", private_key="")

    try:
        assessment = _make_assessment(
            target="https://tamper.example.com/",
            classification=Classification.HIGH_RISK,
            score=80,
        )
        assessment = save_report(assessment, db_path=db_path)
        anchor_report(assessment, settings)

        # Tamper with the SQLite record directly - change the score
        import sqlite3

        conn = sqlite3.connect(db_path)
        cursor = conn.execute("SELECT assessment_json FROM reports WHERE report_id = ?", (assessment.report_id,))
        row = cursor.fetchone()
        data = json.loads(row[0])
        data["score"] = 10  # Change score from 80 to 10
        conn.execute("UPDATE reports SET assessment_json = ?, score = ? WHERE report_id = ?", (json.dumps(data), 10, assessment.report_id))
        conn.commit()
        conn.close()

        # Verify should detect tampering
        result = verify_on_chain(assessment.report_id, settings)

        assert result["integrity_verified"] is False
        assert result["recomputed_hash"] != result["stored_hash"]
        # on_chain_hash should still match original
        assert result["on_chain_hash"] == assessment.report_hash

    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)


def test_verify_on_chain_before_anchoring() -> None:
    """Verify works before anchoring (integrity_verified based on local hash only)."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    settings = Settings(db_path=db_path, rpc_url="", contract_address="", private_key="")

    try:
        assessment = _make_assessment(
            target="https://preanchor.example.com/",
            classification=Classification.LOW_RISK,
            score=10,
        )
        assessment = save_report(assessment, db_path=db_path)

        # Verify before anchoring
        result = verify_on_chain(assessment.report_id, settings)

        assert result["report_id"] == assessment.report_id
        assert result["stored_hash"] == assessment.report_hash
        assert result["recomputed_hash"] == assessment.report_hash
        assert result["on_chain_hash"] is None
        assert result["tx_hash"] is None
        assert result["anchored"] is False
        # Integrity verified should still be True since local hash matches
        assert result["integrity_verified"] is True

    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)


def test_verify_on_chain_nonexistent_report() -> None:
    """Verify raises ValueError for nonexistent report."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    settings = Settings(db_path=db_path, rpc_url="", contract_address="", private_key="")

    try:
        with pytest.raises(ValueError, match="Report not found"):
            verify_on_chain("nonexistent-id", settings)
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_anchor_report_with_message_kind() -> None:
    """Anchor works for message-type assessments too."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    settings = Settings(db_path=db_path, rpc_url="", contract_address="", private_key="")

    try:
        assessment = _make_assessment(
            target="Urgent: Your account is blocked. Send OTP to 12345.",
            kind="message",
            classification=Classification.HIGH_RISK,
            score=70,
            findings=[_make_finding("MSG_CREDENTIAL_REQUEST", Severity.HIGH, "asks for OTP", "message", 40)],
        )
        assessment = save_report(assessment, db_path=db_path)
        result = anchor_report(assessment, settings)

        assert result["mode"] == "local_ledger"
        assert result["tx_hash"].startswith("0x")

        # Verify target_fingerprint is hash of message text
        expected_fingerprint = "0x" + hashlib.sha256(b"Urgent: Your account is blocked. Send OTP to 12345.").hexdigest()
        assert result["target_fingerprint"] == expected_fingerprint

        # Raw message should not be in ledger
        ledger_path = Path(db_path).with_suffix(".chain.json")
        with open(ledger_path, "r") as f:
            ledger_content = f.read()
        assert "blocked" not in ledger_content
        assert "OTP" not in ledger_content

    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)


def test_anchor_report_deterministic_hashes() -> None:
    """Local ledger report_hash and target_fingerprint are deterministic for same inputs."""
    from datetime import datetime, timezone

    fixed_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    settings = Settings(db_path=db_path, rpc_url="", contract_address="", private_key="")

    try:
        assessment1 = _make_assessment(target="https://det.example.com/", score=50, report_id="fixed-id-1", timestamp=fixed_time)
        assessment1 = save_report(assessment1, db_path=db_path)
        result1 = anchor_report(assessment1, settings)

        # Create new DB but same report_id and content
        Path(db_path).unlink(missing_ok=True)
        Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)

        assessment2 = _make_assessment(target="https://det.example.com/", score=50, report_id="fixed-id-1", timestamp=fixed_time)
        assessment2 = save_report(assessment2, db_path=db_path)
        result2 = anchor_report(assessment2, settings)

        # tx_hash will differ due to timestamp, but report_hash and target_fingerprint should be deterministic
        assert result1["report_hash"] == result2["report_hash"]
        assert result1["target_fingerprint"] == result2["target_fingerprint"]

    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)


def test_verify_on_chain_provenance_note() -> None:
    """Verify result includes the required provenance note."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    settings = Settings(db_path=db_path, rpc_url="", contract_address="", private_key="")

    try:
        assessment = _make_assessment(target="https://note.example.com/")
        assessment = save_report(assessment, db_path=db_path)
        anchor_report(assessment, settings)

        result = verify_on_chain(assessment.report_id, settings)

        assert "provenance_note" in result
        assert "Cryptographic commitment verifies report integrity and history" in result["provenance_note"]
        assert "not the ground-truth validity" in result["provenance_note"]

    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)


def test_local_ledger_hash_chain_integrity() -> None:
    """Verify local ledger maintains hash chain (prev_block_hash links)."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    settings = Settings(db_path=db_path, rpc_url="", contract_address="", private_key="")

    try:
        # Anchor multiple reports
        for i in range(3):
            assessment = _make_assessment(target=f"https://chain{i}.example.com/", score=i * 10)
            assessment = save_report(assessment, db_path=db_path)
            anchor_report(assessment, settings)

        # Load ledger and verify chain
        ledger_path = Path(db_path).with_suffix(".chain.json")
        with open(ledger_path, "r") as f:
            ledger = json.load(f)

        assert len(ledger) == 3

        # First block should have genesis prev_block_hash
        assert ledger[0]["prev_block_hash"] == "0x" + "0" * 64

        # Each subsequent block's prev_block_hash should hash to previous block
        for i in range(1, 3):
            prev_block_json = json.dumps(ledger[i - 1], separators=(",", ":"), sort_keys=True)
            expected_prev_hash = "0x" + hashlib.sha256(prev_block_json.encode("utf-8")).hexdigest()
            assert ledger[i]["prev_block_hash"] == expected_prev_hash

    finally:
        Path(db_path).unlink(missing_ok=True)
        Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)