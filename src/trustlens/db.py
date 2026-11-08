"""
TrustLens Database Module

SQLite persistence with threat campaign correlation.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trustlens.config import Settings, get_settings
from trustlens.models import Assessment, Finding


# Canonical fields for report hash computation
_REPORT_HASH_FIELDS = ("kind", "target_hash", "classification", "score", "finding_ids", "timestamp_iso")


def _init_db(db_path: str) -> None:
    """Initialize database tables."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                target TEXT NOT NULL,
                registrable_domain TEXT,
                resolved_ip TEXT,
                impersonated_brand TEXT,
                indicators_json TEXT NOT NULL,
                classification TEXT NOT NULL,
                score INTEGER NOT NULL,
                report_hash TEXT NOT NULL,
                tx_hash TEXT,
                assessment_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_registrable_domain ON reports(registrable_domain)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_resolved_ip ON reports(resolved_ip)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at)"
        )
        conn.commit()
    finally:
        conn.close()


def _compute_target_hash(target: str) -> str:
    """Compute SHA-256 hash of target for privacy-preserving report hash."""
    return hashlib.sha256(target.encode("utf-8")).hexdigest()[:32]


def compute_report_hash(assessment: Assessment) -> str:
    """
    Compute deterministic SHA-256 report hash.

    Hash is computed over canonical JSON of:
    {kind, target_hash, classification, score, finding_ids, timestamp_iso}

    Returns:
        "0x" + 64 hex characters
    """
    finding_ids = sorted(f.id for f in assessment.findings)
    timestamp_iso = assessment.timestamp.isoformat()

    canonical = {
        "kind": assessment.kind,
        "target_hash": _compute_target_hash(assessment.target),
        "classification": assessment.classification.value,
        "score": assessment.score,
        "finding_ids": finding_ids,
        "timestamp_iso": timestamp_iso,
    }

    canonical_json = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return "0x" + digest


def _extract_indicators(assessment: Assessment) -> list[str]:
    """Extract correlation indicators from assessment findings."""
    indicators: set[str] = set()

    for finding in assessment.findings:
        # Extract domains, IPs, UPI IDs, phones from evidence
        evidence = finding.evidence.lower()

        # Look for domain-like patterns
        import re
        domains = re.findall(r"[a-z0-9.-]+\.[a-z]{2,}", evidence)
        for d in domains:
            if not d.startswith("http"):
                indicators.add(d)

        # Look for IP addresses
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", evidence)
        for ip in ips:
            indicators.add(ip)

        # Look for UPI IDs (handle@bank)
        upis = re.findall(r"\b[a-zA-Z0-9._-]+@[a-zA-Z]{2,32}\b", evidence)
        for upi in upis:
            if "." not in upi.split("@")[-1]:
                indicators.add(upi)

        # Look for phone numbers (Indian format)
        phones = re.findall(r"(?:\+91|91|0)?[6-9]\d{9}\b", evidence)
        for phone in phones:
            indicators.add(phone)

    return list(indicators)


def _detect_impersonated_brand(assessment: Assessment) -> str | None:
    """Detect if assessment findings suggest brand impersonation."""
    for finding in assessment.findings:
        if finding.id in ("LEX_BRAND_SUBDOMAIN", "LEX_BRAND_COMBO", "LEX_TYPOSQUAT", "MSG_IMPERSONATION"):
            # Extract brand from evidence
            import re
            match = re.search(r"brand['\s:]+([a-zA-Z0-9\s]+)", finding.evidence, re.IGNORECASE)
            if match:
                return match.group(1).strip()
            match = re.search(r"mimics?\s+['\"]?([a-zA-Z0-9\s]+)['\"]?", finding.evidence, re.IGNORECASE)
            if match:
                return match.group(1).strip()
    return None


def save_report(
    assessment: Assessment,
    db_path: str | None = None,
    registrable_domain: str | None = None,
    resolved_ip: str | None = None,
    indicators: list[str] | None = None,
) -> Assessment:
    """
    Save assessment report to SQLite with correlation.

    Args:
        assessment: The assessment to save
        db_path: Database path (uses settings default if None)
        registrable_domain: Optional registrable domain for correlation
        resolved_ip: Optional resolved IP for correlation
        indicators: Optional list of extracted indicators

    Returns:
        Updated Assessment with report_id, report_hash, and related_reports populated
    """
    if db_path is None:
        settings = get_settings()
        db_path = settings.db_path

    _init_db(db_path)

    # Generate report ID if not present
    if assessment.report_id is None:
        assessment.report_id = str(uuid.uuid4())

    # Compute report hash if not present
    if assessment.report_hash is None:
        assessment.report_hash = compute_report_hash(assessment)

    # Extract indicators if not provided
    if indicators is None:
        indicators = _extract_indicators(assessment)

    # Detect impersonated brand
    impersonated_brand = _detect_impersonated_brand(assessment)

    # Find related reports BEFORE inserting this one
    related = find_related_reports(
        db_path=db_path,
        registrable_domain=registrable_domain,
        resolved_ip=resolved_ip,
        indicators=indicators,
        exclude_report_id=assessment.report_id,
    )

    # Attach related reports to assessment (store as JSON in a field we can use)
    # We'll serialize related reports into assessment_json for now
    assessment_data = assessment.model_dump(mode="json")
    assessment_data["related_reports"] = related

    # Save to database
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO reports (
                report_id, kind, target, registrable_domain, resolved_ip,
                impersonated_brand, indicators_json, classification, score,
                report_hash, tx_hash, assessment_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment.report_id,
                assessment.kind,
                assessment.target,
                registrable_domain,
                resolved_ip,
                impersonated_brand,
                json.dumps(indicators),
                assessment.classification.value,
                assessment.score,
                assessment.report_hash,
                assessment.tx_hash,
                json.dumps(assessment_data),
                assessment.timestamp.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    # Return updated assessment with related_reports
    assessment_dict = assessment.model_dump()
    assessment_dict["related_reports"] = related
    return Assessment(**assessment_dict)


def find_related_reports(
    db_path: str,
    registrable_domain: str | None,
    resolved_ip: str | None,
    indicators: list[str],
    exclude_report_id: str | None = None,
) -> list[dict]:
    """
    Find prior reports sharing indicators.

    Returns up to 5 related report summaries.
    """
    _init_db(db_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        # Build query conditions
        conditions = []
        params = []

        if registrable_domain:
            conditions.append("registrable_domain = ?")
            params.append(registrable_domain)

        if resolved_ip:
            conditions.append("resolved_ip = ?")
            params.append(resolved_ip)

        # Check indicators against stored indicators_json
        for indicator in indicators[:10]:  # Limit to prevent query explosion
            conditions.append("indicators_json LIKE ?")
            params.append(f"%{indicator}%")

        if not conditions:
            return []

        where_clause = " OR ".join(conditions)

        if exclude_report_id:
            where_clause += " AND report_id != ?"
            params.append(exclude_report_id)

        query = f"""
            SELECT report_id, target, classification, indicators_json, created_at, registrable_domain, resolved_ip
            FROM reports
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT 5
        """

        cursor = conn.execute(query, params)
        rows = cursor.fetchall()

        related = []
        for row in rows:
            # Determine which indicator matched
            shared = "unknown"
            if registrable_domain and row["registrable_domain"] == registrable_domain:
                shared = f"domain:{registrable_domain}"
            elif resolved_ip and row["resolved_ip"] == resolved_ip:
                shared = f"ip:{resolved_ip}"
            else:
                try:
                    stored_indicators = json.loads(row["indicators_json"])
                    for ind in indicators:
                        if ind in stored_indicators:
                            shared = f"indicator:{ind}"
                            break
                except (json.JSONDecodeError, TypeError):
                    pass

            related.append(
                {
                    "report_id": row["report_id"],
                    "target": row["target"],
                    "classification": row["classification"],
                    "shared_indicator": shared,
                    "created_at": row["created_at"],
                }
            )

        return related
    finally:
        conn.close()


def get_report(report_id: str, db_path: str | None = None) -> Assessment | None:
    """Retrieve a report by ID."""
    if db_path is None:
        settings = get_settings()
        db_path = settings.db_path

    _init_db(db_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute("SELECT assessment_json FROM reports WHERE report_id = ?", (report_id,))
        row = cursor.fetchone()
        if row:
            data = json.loads(row["assessment_json"])
            return Assessment(**data)
        return None
    finally:
        conn.close()


def list_reports(db_path: str | None = None, limit: int = 20) -> list[dict]:
    """List recent reports."""
    if db_path is None:
        settings = get_settings()
        db_path = settings.db_path

    _init_db(db_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute(
            """
            SELECT report_id, kind, target, classification, score, created_at
            FROM reports
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [
            {
                "report_id": row["report_id"],
                "kind": row["kind"],
                "target": row["target"],
                "classification": row["classification"],
                "score": row["score"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    finally:
        conn.close()