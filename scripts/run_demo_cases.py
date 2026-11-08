#!/usr/bin/env python3
"""
TrustLens Demo Cases Runner

Runs 4 suspicious and 4 benign test cases in deterministic offline mode,
anchors suspicious reports via chain.py, verifies integrity, and writes
results to docs/TESTING_REPORT.md.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

# Ensure offline mode for deterministic results
os.environ["OFFLINE_MODE"] = "1"

from trustlens.chain import anchor_report, verify_on_chain
from trustlens.config import Settings
from trustlens.db import save_report
from trustlens.message.analyze import analyze_message
from trustlens.models import Assessment, CheckStatus, Classification, Finding, Severity
from trustlens.pipeline import analyze_url


# ============================================================================
# Test Cases Definition
# ============================================================================

SUSPICIOUS_CASES = [
    {
        "name": "Threat Feed Match URL",
        "description": "URL matching a known threat intelligence feed (URLhaus/local feed)",
        "kind": "url",
        "target": "http://malicious-phish.example.com/steal-credentials",
        "expected_classification": "confirmed_malicious",
        "expected_findings": ["TI_CRITICAL_FEED_MATCH", "TI_CRITICAL_URLHAUS"],
    },
    {
        "name": "Brand Subdomain Phishing URL",
        "description": "URL with brand name in subdomain (paypal.phishersite.com)",
        "kind": "url",
        "target": "https://paypal.security-update.phishersite.com/login",
        "expected_classification": "high_risk",
        "expected_findings": ["LEX_BRAND_SUBDOMAIN"],
    },
    {
        "name": "Scam SMS with OTP + UPI + Link",
        "description": "SMS message requesting OTP, containing UPI ID and phishing link",
        "kind": "message",
        "target": "URGENT: Your SBI account will be blocked. Share OTP 123456 to verify. Pay via UPI: user@oksbi to unblock. Link: https://sbi-verify.phishersite.com",
        "expected_classification": "high_risk",
        "expected_findings": ["MSG_CREDENTIAL_REQUEST", "MSG_PAYMENT_LURE", "MSG_IMPERSONATION", "MSG_URGENCY_COERCION"],
    },
    {
        "name": "Repeat Campaign Domain (Module 4 Correlation)",
        "description": "Second report sharing domain with first phishing URL - should show campaign correlation",
        "kind": "url",
        "target": "https://paypal.another-page.phishersite.com/verify",
        "expected_classification": "high_risk",
        "expected_findings": ["LEX_BRAND_SUBDOMAIN"],
        "correlates_with": "Brand Subdomain Phishing URL",
    },
]

BENIGN_CASES = [
    {
        "name": "Legitimate Bank Domain",
        "description": "Official State Bank of India domain",
        "kind": "url",
        "target": "https://sbi.co.in",
        "expected_classification": "low_risk",
    },
    {
        "name": "Legitimate University Domain",
        "description": "Official Adamas University domain",
        "kind": "url",
        "target": "https://adamasuniversity.ac.in",
        "expected_classification": "low_risk",
    },
    {
        "name": "Legitimate GitHub Login",
        "description": "Official GitHub login page",
        "kind": "url",
        "target": "https://github.com/login",
        "expected_classification": "low_risk",
    },
    {
        "name": "Benign Urgent Reminder Message",
        "description": "Legitimate appointment reminder without credential/financial requests",
        "kind": "message",
        "target": "Reminder: Your dentist appointment is tomorrow at 10 AM. Please arrive 10 minutes early. Reply STOP to opt out.",
        "expected_classification": "low_risk",
    },
]


# ============================================================================
# Helper Functions
# ============================================================================

async def run_url_assessment(target: str, settings: Settings) -> Assessment:
    """Run URL assessment in offline mode."""
    return await analyze_url(
        target,
        _settings=settings,
        save_to_db=True,
        generate_explanation_flag=True,
        db_path=settings.db_path,
    )


async def run_message_assessment(text: str, settings: Settings) -> Assessment:
    """Run message assessment in offline mode."""
    return await analyze_message(
        text,
        settings=settings,
        save_to_db=True,
        generate_explanation_flag=True,
        db_path=settings.db_path,
    )


def format_assessment_summary(assessment: Assessment, case: dict) -> str:
    """Format assessment as markdown for the report."""
    lines = []
    lines.append(f"### {case['name']}")
    lines.append(f"**Target:** `{assessment.target[:100]}{'...' if len(assessment.target) > 100 else ''}`")
    lines.append(f"**Kind:** {assessment.kind}")
    lines.append(f"**Classification:** {assessment.classification.value}")
    lines.append(f"**Score:** {assessment.score}/100")
    lines.append(f"**Coverage:** {int(assessment.coverage * 100)}%")
    lines.append(f"**Report ID:** {assessment.report_id}")
    lines.append(f"**Report Hash:** {assessment.report_hash}")

    if assessment.findings:
        lines.append("\n**Findings:**")
        for f in assessment.findings:
            lines.append(f"- **{f.id}** ({f.severity.value.upper()}): {f.evidence[:150]}")
    else:
        lines.append("\n**Findings:** None")

    if assessment.unavailable_checks:
        lines.append(f"\n**Unavailable Checks:** {', '.join(assessment.unavailable_checks)}")

    if assessment.related_reports:
        lines.append(f"\n**Campaign Correlations:** {len(assessment.related_reports)} related report(s)")
        for r in assessment.related_reports:
            lines.append(f"  - {r['report_id'][:8]}... via {r['shared_indicator']}")

    if assessment.explanation:
        lines.append(f"\n**Explanation:** {assessment.explanation[:300]}...")

    return "\n".join(lines)


def format_anchor_result(result: dict) -> str:
    """Format anchor result as markdown."""
    lines = ["\n**Anchoring Result:**"]
    lines.append(f"- **Mode:** {result['mode']}")
    lines.append(f"- **Tx Hash:** {result['tx_hash']}")
    lines.append(f"- **Report Hash:** {result['report_hash']}")
    lines.append(f"- **Target Fingerprint:** {result['target_fingerprint']}")
    if result.get("block_number"):
        lines.append(f"- **Block Number:** {result['block_number']}")
    if result.get("contract_address"):
        lines.append(f"- **Contract Address:** {result['contract_address']}")
    return "\n".join(lines)


def format_verify_result(result: dict) -> str:
    """Format verification result as markdown."""
    lines = ["\n**Verification Result:**"]
    lines.append(f"- **Anchored:** {result['anchored']}")
    lines.append(f"- **Integrity Verified:** {result['integrity_verified']}")
    lines.append(f"- **Stored Hash:** {result['stored_hash']}")
    lines.append(f"- **Recomputed Hash:** {result['recomputed_hash']}")
    lines.append(f"- **On-Chain Hash:** {result['on_chain_hash']}")
    lines.append(f"- **Tx Hash:** {result['tx_hash']}")
    lines.append(f"- **Target Fingerprint:** {result['target_fingerprint']}")
    lines.append(f"- **Provenance Note:** {result['provenance_note']}")
    return "\n".join(lines)


# ============================================================================
# Main Runner
# ============================================================================

async def main():
    # Create temp database for isolation
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    # Settings with offline mode and local ledger
    settings = Settings(
        db_path=db_path,
        offline_mode=True,
        rpc_url="",
        contract_address="",
        private_key="",
    )

    print(f"Using database: {db_path}")
    print("Running in OFFLINE_MODE for deterministic results\n")

    report_sections = []
    suspicious_reports = []

    # ---------------------------------------------------------
    # Run Suspicious Cases
    # ---------------------------------------------------------
    report_sections.append("# TrustLens Demo Test Report")
    report_sections.append(f"\n**Generated:** {datetime.now().isoformat()}")
    report_sections.append(f"**Database:** {db_path}")
    report_sections.append("**Mode:** Offline (deterministic)")
    report_sections.append("\n---\n")

    report_sections.append("## Suspicious Test Cases")
    report_sections.append("\n*These cases should trigger HIGH_RISK or CONFIRMED_MALICIOUS classifications.*\n")

    for i, case in enumerate(SUSPICIOUS_CASES):
        print(f"[{i+1}/8] Running suspicious case: {case['name']}")

        if case["kind"] == "url":
            assessment = await run_url_assessment(case["target"], settings)
        else:
            assessment = await run_message_assessment(case["target"], settings)

        suspicious_reports.append(assessment)

        # Format assessment
        report_sections.append(format_assessment_summary(assessment, case))

        # Check expected classification
        expected = case.get("expected_classification")
        actual = assessment.classification.value
        match = "✅ MATCH" if expected == actual else f"❌ MISMATCH (expected {expected})"
        report_sections.append(f"\n**Expected Classification:** {expected} — {match}")

        # Anchor the suspicious report
        print(f"  Anchoring report {assessment.report_id[:8]}...")
        anchor_result = anchor_report(assessment, settings)
        report_sections.append(format_anchor_result(anchor_result))

        # Verify integrity
        print(f"  Verifying integrity...")
        verify_result = verify_on_chain(assessment.report_id, settings)
        report_sections.append(format_verify_result(verify_result))

        report_sections.append("\n---\n")

    # ---------------------------------------------------------
    # Run Benign Cases
    # ---------------------------------------------------------
    report_sections.append("## Benign Test Cases")
    report_sections.append("\n*These cases should result in LOW_RISK classifications.*\n")

    for i, case in enumerate(BENIGN_CASES):
        print(f"[{i+5}/8] Running benign case: {case['name']}")

        if case["kind"] == "url":
            assessment = await run_url_assessment(case["target"], settings)
        else:
            assessment = await run_message_assessment(case["target"], settings)

        report_sections.append(format_assessment_summary(assessment, case))

        expected = case.get("expected_classification")
        actual = assessment.classification.value
        match = "✅ MATCH" if expected == actual else f"❌ MISMATCH (expected {expected})"
        report_sections.append(f"\n**Expected Classification:** {expected} — {match}")

        report_sections.append("\n---\n")

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------
    report_sections.append("## Summary")
    report_sections.append(f"\n**Total Cases:** 8 (4 suspicious, 4 benign)")
    report_sections.append(f"**Suspicious Reports Anchored:** {len(suspicious_reports)}")
    report_sections.append(f"**All Integrity Verified:** {all(verify_on_chain(r.report_id, settings)['integrity_verified'] for r in suspicious_reports)}")

    # Verify campaign correlation for repeat domain case
    if len(suspicious_reports) >= 4:
        last_report = suspicious_reports[3]
        if last_report.related_reports:
            report_sections.append(f"\n**Campaign Correlation Detected:** Yes ({len(last_report.related_reports)} related)")
            for r in last_report.related_reports:
                report_sections.append(f"  - Related to {r['report_id'][:8]}... via {r['shared_indicator']}")
        else:
            report_sections.append("\n**Campaign Correlation Detected:** No")

    report_sections.append("\n---\n")
    report_sections.append("*Report generated by TrustLens automated demo runner.*")

    # Write report
    report_content = "\n".join(report_sections)
    report_path = Path("docs/TESTING_REPORT.md")
    report_path.write_text(report_content)
    print(f"\n✅ Report written to {report_path}")

    # Cleanup
    Path(db_path).unlink(missing_ok=True)
    Path(db_path).with_suffix(".chain.json").unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())