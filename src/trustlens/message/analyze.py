"""
TrustLens Message Analysis

Analyzes message text for social engineering patterns, credential harvesting,
urgency coercion, payment lures, impersonation, and correlates with URL analysis.
"""

from __future__ import annotations

import re
from typing import Any

from trustlens.config import Settings, get_settings
from trustlens.db import save_report
from trustlens.explain import generate_explanation
from trustlens.message.extract import extract_all
from trustlens.models import Assessment, CheckStatus, Finding, Severity
from trustlens.pipeline import analyze_url
from trustlens.scoring import build_assessment


# Credential harvesting keywords (longer phrases first for priority matching)
CREDENTIAL_KEYWORDS = (
    "netbanking password",
    "seed phrase",
    "private key",
    "recovery phrase",
    "atm pin",
    "upi pin",
    "mpin",
    "otp",
    "cvv",
    "pin",
    "password",
)

# Urgency/coercion keywords (LOW severity, weight <= 15)
URGENCY_KEYWORDS = (
    "account blocked",
    "account suspended",
    "kyc expire",
    "within 24 hours",
    "immediately",
    "pan card blocked",
    "electricity disconnected",
    "legal action",
    "urgent",
    "last warning",
    "final notice",
    "act now",
    "expires today",
)

# Payment/financial lure keywords
PAYMENT_LURE_KEYWORDS = (
    "send ₹",
    "pay via upi",
    "processing fee",
    "registration fee",
    "lottery",
    "won prize",
    "double your crypto",
    "airdrop claim",
    "airdrop",
    "part-time job",
    "telegram task",
    "work from home",
    "easy money",
    "investment opportunity",
    "guaranteed return",
)

# Organization impersonation keywords
IMPERSONATION_KEYWORDS = (
    "state bank",
    "sbi",
    "hdfc",
    "icici",
    "rbi",
    "income tax",
    "irctc",
    "customs",
    "fedex",
    "university",
    "amazon",
    "flipkart",
    "google",
    "microsoft",
    "paytm",
    "phonepe",
)


def _check_credential_request(text: str) -> Finding | None:
    """Check for credential/secret harvesting language."""
    text_lower = text.lower()
    for kw in CREDENTIAL_KEYWORDS:
        if kw in text_lower:
            return Finding(
                id="MSG_CREDENTIAL_REQUEST",
                check="message",
                title="Credential or secret harvesting request",
                severity=Severity.HIGH,
                evidence=f"Message requests sensitive information: '{kw}'",
                source="message_analysis",
                confidence=0.85,
                weight=40,
                impact="Requests for OTP, PIN, passwords, or seed phrases are hallmarks of account takeover attempts",
                recommendation="Never share OTP, PIN, passwords, seed phrases, or private keys with anyone",
            )
    return None


def _check_urgency_coercion(text: str) -> Finding | None:
    """Check for urgency/coercion language (LOW severity, weight <= 15)."""
    text_lower = text.lower()
    for kw in URGENCY_KEYWORDS:
        if kw in text_lower:
            return Finding(
                id="MSG_URGENCY_COERCION",
                check="message",
                title="Urgency or coercion language detected",
                severity=Severity.LOW,
                evidence=f"Message uses urgency tactic: '{kw}'",
                source="message_analysis",
                confidence=0.65,
                weight=15,
                impact="Urgency tactics pressure victims to act without verification",
                recommendation="Take time to verify independently; legitimate organizations don't demand instant action via unsolicited messages",
            )
    return None


def _check_payment_lure(text: str, upi_ids: list[Any]) -> Finding | None:
    """Check for suspicious payment/financial lure language."""
    text_lower = text.lower()

    # Check for payment lure keywords
    for kw in PAYMENT_LURE_KEYWORDS:
        if kw in text_lower:
            return Finding(
                id="MSG_PAYMENT_LURE",
                check="message",
                title="Suspicious payment or financial lure",
                severity=Severity.MEDIUM,
                evidence=f"Message contains financial lure: '{kw}'",
                source="message_analysis",
                confidence=0.75,
                weight=30,
                impact="Financial lures entice victims to send money or share payment details",
                recommendation="Verify independently; never pay fees to claim prizes, airdrops, or jobs",
            )

    # Check for UPI IDs alongside urgency/lure language
    if upi_ids:
        # Check if there's also urgency or lure language
        has_urgency = any(kw in text_lower for kw in URGENCY_KEYWORDS)
        has_lure = any(kw in text_lower for kw in PAYMENT_LURE_KEYWORDS)
        if has_urgency or has_lure:
            upi_str = ", ".join(u.original for u in upi_ids)
            return Finding(
                id="MSG_PAYMENT_LURE",
                check="message",
                title="UPI payment request with urgency/lure language",
                severity=Severity.MEDIUM,
                evidence=f"Message contains UPI ID(s): {upi_str} alongside urgency/lure language",
                source="message_analysis",
                confidence=0.8,
                weight=30,
                impact="UPI requests combined with urgency are common in payment fraud",
                recommendation="Verify UPI ID independently; don't pay under pressure",
            )

    return None


def _check_impersonation(text: str, extracted_urls: list[Any], upi_ids: list[Any], credential_request: bool) -> Finding | None:
    """Check for organization impersonation claims."""
    text_lower = text.lower()

    for kw in IMPERSONATION_KEYWORDS:
        if kw in text_lower:
            # Check if combined with unverified link, UPI handle, or credential request
            has_unverified_link = len(extracted_urls) > 0
            has_upi = len(upi_ids) > 0

            if has_unverified_link or has_upi or credential_request:
                return Finding(
                    id="MSG_IMPERSONATION",
                    check="message",
                    title="Organization impersonation claim with suspicious indicators",
                    severity=Severity.MEDIUM,
                    evidence=f"Message claims to be from '{kw}' and contains {'unverified link(s)' if has_unverified_link else ''}{' UPI ID(s)' if has_upi else ''}{' credential request' if credential_request else ''}",
                    source="message_analysis",
                    confidence=0.75,
                    weight=25,
                    impact="Impersonation of trusted organizations is a core phishing/smishing technique",
                    recommendation="Contact the organization directly through official channels; don't trust unsolicited messages",
                )
    return None


def _extract_indicators_for_correlation(extraction, text: str) -> list[str]:
    """Extract indicators for campaign correlation."""
    indicators: set[str] = set()

    # Add extracted URLs' domains
    for url in extraction.urls:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url.refanged)
            if parsed.netloc:
                indicators.add(parsed.netloc)
        except Exception:
            pass

    # Add UPI IDs
    for upi in extraction.upi_ids:
        indicators.add(upi.original)

    # Add phones
    for phone in extraction.phones:
        indicators.add(phone.normalized)

    # Add emails
    for email in extraction.emails:
        indicators.add(email.refanged)

    return list(indicators)


async def analyze_message(
    text: str,
    settings: Settings | None = None,
    save_to_db: bool = True,
    generate_explanation_flag: bool = True,
    db_path: str | None = None,
) -> Assessment:
    """
    Analyze a message for scam/fraud indicators.

    Args:
        text: Message text to analyze
        settings: Optional settings for URL analysis
        save_to_db: Whether to save report to database
        generate_explanation_flag: Whether to generate AI explanation
        db_path: Optional database path for saving

    Returns:
        Assessment with message analysis findings
    """
    if settings is None:
        settings = get_settings()

    # Cap text length
    text = text[:10000]

    # Extract indicators
    extraction = extract_all(text)

    # Run deterministic social-engineering rules
    findings: list[Finding] = []

    # 1. Credential request check
    cred_finding = _check_credential_request(text)
    if cred_finding:
        findings.append(cred_finding)
    has_credential_request = cred_finding is not None

    # 2. Urgency coercion check
    urgency_finding = _check_urgency_coercion(text)
    if urgency_finding:
        findings.append(urgency_finding)

    # 3. Payment lure check
    payment_finding = _check_payment_lure(text, extraction.upi_ids)
    if payment_finding:
        findings.append(payment_finding)

    # 4. Impersonation check
    impersonation_finding = _check_impersonation(text, extraction.urls, extraction.upi_ids, has_credential_request)
    if impersonation_finding:
        findings.append(impersonation_finding)

    # 5. Correlate extracted URLs (up to first 3)
    checks: list = [CheckStatus(check="message", ran=True, reason=None)]
    for i, extracted_url in enumerate(extraction.urls[:3]):
        try:
            url_assessment = await analyze_url(extracted_url.refanged, _settings=settings)
            # Fold URL findings into message findings
            for finding in url_assessment.findings:
                # Preserve TI_CRITICAL* findings
                if finding.id.startswith("TI_CRITICAL"):
                    finding.check = "message"  # Mark as from message analysis
                    finding.source = "message_url_correlation"
                findings.append(finding)
            checks.extend(url_assessment.checks)
        except Exception:
            # If URL analysis fails, continue with other URLs
            pass

    # Build assessment
    assessment = build_assessment(
        target=text[:200],
        findings=findings,
        checks=checks,
        kind="message",
    )

    # Extract indicators for correlation
    indicators = _extract_indicators_for_correlation(extraction, text)

    # Save to database and get campaign correlations
    if save_to_db:
        assessment = save_report(
            assessment,
            indicators=indicators,
            db_path=db_path,
        )

    # Generate explanation
    if generate_explanation_flag:
        assessment.explanation = await generate_explanation(assessment, settings)

    return assessment