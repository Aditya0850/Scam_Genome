"""
TrustLens HTTP Security Headers Check

Passive analysis of HTTP response headers for security configuration.
"""

from __future__ import annotations

from trustlens.checks.normalise import NormalisedUrl
from trustlens.models import CheckStatus, FetchResult, Finding, Severity


def _has_frame_ancestors(csp_value: str) -> bool:
    """Check if CSP contains frame-ancestors directive."""
    return "frame-ancestors" in csp_value.lower()


def run(target: NormalisedUrl, fetch: FetchResult) -> tuple[list[Finding], CheckStatus]:
    """
    Run security headers analysis on fetch response.

    Args:
        target: NormalisedUrl that was fetched
        fetch: FetchResult from safefetch

    Returns:
        Tuple of (findings, check_status)
    """
    findings: list[Finding] = []

    if not fetch.ok:
        return [], CheckStatus(
            check="headers",
            ran=False,
            reason="HTTP fetch did not succeed",
        )

    # Lowercase headers for case-insensitive lookup
    headers = {k.lower(): v for k, v in fetch.headers.items()}

    # 1. Check for HSTS (only relevant for HTTPS)
    is_https = target.scheme == "https" or (fetch.final_url and fetch.final_url.startswith("https://"))
    if is_https and "strict-transport-security" not in headers:
        findings.append(
            Finding(
                id="HDR_MISSING_HSTS",
                check="headers",
                title="Missing Strict-Transport-Security header",
                severity=Severity.LOW,
                evidence="Response lacks HSTS header on HTTPS endpoint",
                source="headers_analysis",
                confidence=0.9,
                weight=5,
                impact="Without HSTS, users may be vulnerable to SSL stripping attacks",
                recommendation="Add Strict-Transport-Security header with appropriate max-age",
            )
        )

    # 2. Check for Content-Security-Policy
    if "content-security-policy" not in headers:
        findings.append(
            Finding(
                id="HDR_MISSING_CSP",
                check="headers",
                title="Missing Content-Security-Policy header",
                severity=Severity.LOW,
                evidence="Response lacks CSP header",
                source="headers_analysis",
                confidence=0.9,
                weight=5,
                impact="Without CSP, the page is more vulnerable to XSS and injection attacks",
                recommendation="Implement a restrictive Content-Security-Policy header",
            )
        )

    # 3. Check for clickjacking protection (X-Frame-Options or frame-ancestors in CSP)
    has_xfo = "x-frame-options" in headers
    has_csp_frame_ancestors = "content-security-policy" in headers and _has_frame_ancestors(headers["content-security-policy"])

    if not has_xfo and not has_csp_frame_ancestors:
        findings.append(
            Finding(
                id="HDR_MISSING_CLICKJACK",
                check="headers",
                title="Missing clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
                severity=Severity.LOW,
                evidence="Response lacks X-Frame-Options and CSP frame-ancestors directive",
                source="headers_analysis",
                confidence=0.9,
                weight=5,
                impact="Page may be embedded in iframes on malicious sites for clickjacking",
                recommendation="Add X-Frame-Options: DENY or SAMEORIGIN, or CSP frame-ancestors directive",
            )
        )

    # 4. Check for X-Content-Type-Options: nosniff
    x_content_type = headers.get("x-content-type-options", "").lower()
    if "nosniff" not in x_content_type:
        findings.append(
            Finding(
                id="HDR_MISSING_NOSNIFF",
                check="headers",
                title="Missing X-Content-Type-Options: nosniff",
                severity=Severity.INFO,
                evidence=f"X-Content-Type-Options value: {headers.get('x-content-type-options', 'absent')}",
                source="headers_analysis",
                confidence=0.8,
                weight=0,
                impact="Browser may MIME-sniff responses, potentially executing unintended content types",
                recommendation="Add X-Content-Type-Options: nosniff header",
            )
        )

    return findings, CheckStatus(check="headers", ran=True, reason=None)