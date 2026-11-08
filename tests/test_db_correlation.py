"""Tests for trustlens.db (SQLite persistence and campaign correlation)."""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from trustlens.db import compute_report_hash, find_related_reports, get_report, list_reports, save_report
from trustlens.models import Assessment, Classification, CheckStatus, Finding, Severity


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
    return Assessment(
        kind=kind,
        target=target,
        classification=classification,
        score=score,
        findings=findings,
        checks=checks,
        coverage=1.0,
        report_id=report_id,
        timestamp=timestamp or datetime.now(timezone.utc),
    )


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


def test_compute_report_hash_deterministic() -> None:
    """Report hash should be deterministic for same inputs."""
    fixed_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    a1 = _make_assessment(target="https://example.com/", score=10, timestamp=fixed_time)
    a2 = _make_assessment(target="https://example.com/", score=10, timestamp=fixed_time)

    # Same target, classification, score, findings -> same hash
    h1 = compute_report_hash(a1)
    h2 = compute_report_hash(a2)
    assert h1 == h2
    assert h1.startswith("0x")
    assert len(h1) == 66  # 0x + 64 hex chars


def test_compute_report_hash_different_on_change() -> None:
    """Report hash should change when inputs change."""
    a1 = _make_assessment(target="https://example.com/", score=10)
    a2 = _make_assessment(target="https://example.com/", score=20)  # Different score

    h1 = compute_report_hash(a1)
    h2 = compute_report_hash(a2)
    assert h1 != h2


def test_save_report_assigns_id_and_hash() -> None:
    """save_report should assign report_id and report_hash."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        assessment = _make_assessment()
        assert assessment.report_id is None
        assert assessment.report_hash is None

        saved = save_report(assessment, db_path=db_path)

        assert saved.report_id is not None
        assert saved.report_hash is not None
        assert saved.report_hash.startswith("0x")
        assert len(saved.report_hash) == 66
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_save_report_persists_to_db() -> None:
    """save_report should persist assessment to SQLite."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        assessment = _make_assessment(target="https://test.example.com/")
        saved = save_report(assessment, db_path=db_path)

        # Retrieve and verify
        retrieved = get_report(saved.report_id, db_path=db_path)
        assert retrieved is not None
        assert retrieved.target == "https://test.example.com/"
        assert retrieved.classification == Classification.LOW_RISK
        assert retrieved.report_hash == saved.report_hash
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_correlation_same_registrable_domain() -> None:
    """Reports sharing registrable_domain should correlate."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        # First report
        a1 = _make_assessment(target="https://phish.example.com/login")
        a1 = save_report(a1, db_path=db_path, registrable_domain="example.com")

        # Second report with same registrable domain
        a2 = _make_assessment(target="https://evil.example.com/verify")
        a2 = save_report(a2, db_path=db_path, registrable_domain="example.com")

        # Check correlation
        assert len(a2.related_reports) == 1
        assert a2.related_reports[0]["report_id"] == a1.report_id
        assert "domain:example.com" in a2.related_reports[0]["shared_indicator"]
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_correlation_same_resolved_ip() -> None:
    """Reports sharing resolved_ip should correlate."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        a1 = _make_assessment(target="https://site1.com/")
        a1 = save_report(a1, db_path=db_path, resolved_ip="192.0.2.1")

        a2 = _make_assessment(target="https://site2.com/")
        a2 = save_report(a2, db_path=db_path, resolved_ip="192.0.2.1")

        assert len(a2.related_reports) == 1
        assert a2.related_reports[0]["report_id"] == a1.report_id
        assert "ip:192.0.2.1" in a2.related_reports[0]["shared_indicator"]
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_correlation_shared_upi_indicator() -> None:
    """Reports sharing UPI ID indicator should correlate."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        # Create assessment with UPI-like evidence
        upi_finding = _make_finding(
            finding_id="MSG_PAYMENT_LURE",
            evidence="Message contains UPI ID: user@oksbi",
            weight=30,
        )
        a1 = _make_assessment(findings=[upi_finding])
        a1 = save_report(a1, db_path=db_path, indicators=["user@oksbi"])

        a2 = _make_assessment(target="Another message")
        a2 = save_report(a2, db_path=db_path, indicators=["user@oksbi"])

        assert len(a2.related_reports) == 1
        assert a2.related_reports[0]["report_id"] == a1.report_id
        assert "indicator:user@oksbi" in a2.related_reports[0]["shared_indicator"]
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_correlation_shared_phone_indicator() -> None:
    """Reports sharing phone indicator should correlate."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        a1 = _make_assessment()
        a1 = save_report(a1, db_path=db_path, indicators=["+919876543210"])

        a2 = _make_assessment()
        a2 = save_report(a2, db_path=db_path, indicators=["+919876543210"])

        assert len(a2.related_reports) == 1
        assert "indicator:+919876543210" in a2.related_reports[0]["shared_indicator"]
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_correlation_shared_domain_indicator() -> None:
    """Reports sharing domain indicator should correlate."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        a1 = _make_assessment()
        a1 = save_report(a1, db_path=db_path, indicators=["phish.example.com"])

        a2 = _make_assessment()
        a2 = save_report(a2, db_path=db_path, indicators=["phish.example.com"])

        assert len(a2.related_reports) == 1
        assert "indicator:phish.example.com" in a2.related_reports[0]["shared_indicator"]
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_find_related_reports_excludes_current() -> None:
    """find_related_reports should exclude the current report by ID."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        a1 = _make_assessment(report_id="fixed-id-1")
        a1 = save_report(a1, db_path=db_path, registrable_domain="example.com")

        a2 = _make_assessment(report_id="fixed-id-2")
        a2 = save_report(a2, db_path=db_path, registrable_domain="example.com")

        # Query excluding a2
        related = find_related_reports(
            db_path=db_path,
            registrable_domain="example.com",
            resolved_ip=None,
            indicators=[],
            exclude_report_id="fixed-id-2",
        )
        assert len(related) == 1
        assert related[0]["report_id"] == "fixed-id-1"
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_list_reports() -> None:
    """list_reports should return recent reports."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        for i in range(3):
            a = _make_assessment(target=f"https://site{i}.com/")
            save_report(a, db_path=db_path)

        reports = list_reports(db_path=db_path, limit=10)
        assert len(reports) == 3
        assert all("report_id" in r for r in reports)
        assert all("classification" in r for r in reports)
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_report_hash_integrity() -> None:
    """Verify report_hash matches recomputed hash from stored assessment."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        a1 = _make_assessment(target="https://integrity.test/", score=42)
        saved = save_report(a1, db_path=db_path)

        # Retrieve raw stored data
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT assessment_json, report_hash FROM reports WHERE report_id = ?", (saved.report_id,))
        row = cursor.fetchone()
        conn.close()

        stored_hash = row["report_hash"]
        stored_assessment = json.loads(row["assessment_json"])

        # Recompute hash from stored assessment data
        recomputed = compute_report_hash(Assessment(**stored_assessment))
        assert recomputed == stored_hash
    finally:
        Path(db_path).unlink(missing_ok=True)


def test_get_report_nonexistent() -> None:
    """get_report should return None for nonexistent report."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        result = get_report("nonexistent-id", db_path=db_path)
        assert result is None
    finally:
        Path(db_path).unlink(missing_ok=True)