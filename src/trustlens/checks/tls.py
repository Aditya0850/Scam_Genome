"""
TrustLens TLS & Web Trust Analysis

Analyzes TLS certificates for security issues including expiration,
hostname mismatch, weak cryptography, untrusted issuers, and distrusted CAs.
"""

from __future__ import annotations

import asyncio
import fnmatch
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import cryptography.x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from trustlens.checks.normalise import NormalisedUrl
from trustlens.checks.safefetch import is_ip_allowed
from trustlens.models import CheckStatus, Finding, Severity


# Distrusted CA patterns (lowercase for case-insensitive matching)
DISTRUSTED_CA_PATTERNS = (
    "emudhra",
    "trustcor",
    "wo-sign",
    "wosign",
    "startcom",
    "symantec",
)


def _extract_sans(cert: cryptography.x509.Certificate) -> list[str]:
    """Extract Subject Alternative Names (DNSNames and IPAddresses) from certificate."""
    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, cryptography.x509.DNSName):
                # DNSName.value gives the domain name
                sans.append(name.value)
            elif isinstance(name, cryptography.x509.IPAddress):
                sans.append(str(name.value))
    except cryptography.x509.ExtensionNotFound:
        pass
    return sans


def _extract_cn(cert: cryptography.x509.Certificate) -> str | None:
    """Extract Common Name from certificate subject."""
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(cryptography.x509.NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
    except Exception:
        pass
    return None


def _matches_hostname(pattern: str, hostname: str) -> bool:
    """
    Check if hostname matches a certificate pattern (supports single-label wildcards).

    Uses fnmatch-style matching for *.example.com patterns.
    """
    pattern = pattern.lower().strip()
    hostname = hostname.lower().strip()

    # Direct match
    if pattern == hostname:
        return True

    # Single-label wildcard matching (e.g., *.example.com matches a.example.com)
    if pattern.startswith("*."):
        suffix = pattern[2:]  # Remove "*."
        # Check if hostname ends with the suffix
        if hostname == suffix or hostname.endswith("." + suffix):
            # Ensure only one label before the suffix (single-label wildcard)
            if hostname == suffix:
                return True
            prefix = hostname[: -len(suffix) - 1]  # Remove ".suffix"
            if prefix and "." not in prefix:
                return True

    return False


def _get_issuer_name(cert: cryptography.x509.Certificate) -> str:
    """Get human-readable issuer name."""
    try:
        org_attrs = cert.issuer.get_attributes_for_oid(cryptography.x509.NameOID.ORGANIZATION_NAME)
        if org_attrs:
            return org_attrs[0].value
        cn_attrs = cert.issuer.get_attributes_for_oid(cryptography.x509.NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
    except Exception:
        pass
    return "Unknown"


def _check_weak_crypto(cert: cryptography.x509.Certificate) -> tuple[bool, str]:
    """
    Check for weak cryptography in certificate.

    Returns:
        Tuple of (is_weak, evidence_string)
    """
    public_key = cert.public_key()
    sig_alg = cert.signature_hash_algorithm

    # Check signature algorithm
    if sig_alg is not None:
        alg_name = sig_alg.name.lower()
        if alg_name in {"md5", "sha1"}:
            return True, f"Weak signature algorithm: {alg_name.upper()}"

    # Check key size
    if isinstance(public_key, rsa.RSAPublicKey):
        key_size = public_key.key_size
        if key_size < 2048:
            return True, f"RSA key size {key_size} bits (< 2048)"
    elif isinstance(public_key, dsa.DSAPublicKey):
        key_size = public_key.key_size
        if key_size < 2048:
            return True, f"DSA key size {key_size} bits (< 2048)"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_size = public_key.curve.key_size
        if key_size < 224:
            return True, f"EC key size {key_size} bits (< 224)"

    return False, ""


def _check_distrusted_ca(cert: cryptography.x509.Certificate) -> tuple[bool, str]:
    """
    Check if certificate issuer is a distrusted/compromised CA.

    Returns:
        Tuple of (is_distrusted, evidence_string)
    """
    issuer_name = _get_issuer_name(cert).lower()

    for pattern in DISTRUSTED_CA_PATTERNS:
        if pattern in issuer_name:
            return True, f"Distrusted CA detected: {_get_issuer_name(cert)} (matches {pattern})"

    return False, ""


def inspect_certificate(
    cert: cryptography.x509.Certificate,
    hostname: str,
    verified_chain: bool = True,
) -> list[Finding]:
    """
    Inspect a TLS certificate for security issues.

    Args:
        cert: The x509 certificate to inspect
        hostname: The hostname to verify against
        verified_chain: Whether the certificate chain was verified

    Returns:
        List of Finding objects for any issues found
    """
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    # 1. Check certificate validity period
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    if now < not_before:
        findings.append(
            Finding(
                id="TLS_CERT_EXPIRED",
                check="tls",
                title="Certificate not yet valid",
                severity=Severity.HIGH,
                evidence=f"Certificate not valid before {not_before.isoformat()}, current time: {now.isoformat()}",
                source="tls_certificate_analysis",
                confidence=0.95,
                weight=35,
                impact="Certificate is not yet valid; connection should not be trusted",
                recommendation="Verify system clock and certificate validity period",
            )
        )
    elif now > not_after:
        findings.append(
            Finding(
                id="TLS_CERT_EXPIRED",
                check="tls",
                title="Certificate expired",
                severity=Severity.HIGH,
                evidence=f"Certificate expired on {not_after.isoformat()}, current time: {now.isoformat()}",
                source="tls_certificate_analysis",
                confidence=0.95,
                weight=35,
                impact="Expired certificate indicates poor security hygiene or potential MITM",
                recommendation="Do not trust this connection; contact site administrator",
            )
        )

    # 2. Check hostname / SAN mismatch
    sans = _extract_sans(cert)
    cn = _extract_cn(cert)

    hostname_match = False
    if sans:
        for san in sans:
            if _matches_hostname(san, hostname):
                hostname_match = True
                break
    elif cn:
        hostname_match = _matches_hostname(cn, hostname)

    if not hostname_match:
        expected = ", ".join(sans) if sans else (cn or "none")
        findings.append(
            Finding(
                id="TLS_HOSTNAME_MISMATCH",
                check="tls",
                title="Certificate hostname mismatch",
                severity=Severity.HIGH,
                evidence=f"Expected host: {hostname}; Certificate SANs/CN: {expected}",
                source="tls_certificate_analysis",
                confidence=0.95,
                weight=35,
                impact="Hostname mismatch indicates potential MITM or misconfigured certificate",
                recommendation="Do not proceed; verify you are connecting to the correct domain",
            )
        )

    # 3. Check untrusted / self-signed issuer
    if not verified_chain or cert.issuer == cert.subject:
        findings.append(
            Finding(
                id="TLS_UNTRUSTED_ISSUER",
                check="tls",
                title="Untrusted or self-signed certificate",
                severity=Severity.HIGH,
                evidence=f"Verified chain: {verified_chain}; Issuer: {_get_issuer_name(cert)}; Subject: {cert.subject}",
                source="tls_certificate_analysis",
                confidence=0.9,
                weight=35,
                impact="Self-signed or untrusted certificates offer no authentication guarantee",
                recommendation="Do not trust this connection; verify certificate through trusted CA",
            )
        )

    # 4. Check weak cryptography
    is_weak, weak_evidence = _check_weak_crypto(cert)
    if is_weak:
        findings.append(
            Finding(
                id="TLS_WEAK_CRYPTO",
                check="tls",
                title="Weak cryptography in certificate",
                severity=Severity.MEDIUM,
                evidence=weak_evidence,
                source="tls_certificate_analysis",
                confidence=0.9,
                weight=20,
                impact="Weak keys or signature algorithms are vulnerable to cryptographic attacks",
                recommendation="Require certificates with RSA >= 2048 bits, EC >= 224 bits, and SHA-256+ signatures",
            )
        )

    # 5. Check distrusted CA
    is_distrusted, distrusted_evidence = _check_distrusted_ca(cert)
    if is_distrusted:
        findings.append(
            Finding(
                id="TLS_DISTRUSTED_CA",
                check="tls",
                title="Certificate issued by distrusted/compromised CA",
                severity=Severity.HIGH,
                evidence=distrusted_evidence,
                source="tls_certificate_analysis",
                confidence=0.85,
                weight=40,
                impact="Certificates from distrusted CAs may have been compromised; browser trust has been revoked",
                recommendation="Do not trust this connection; CA has known trust incidents. Note: URL inspection identifies CA lineage, not internal CA key-generation flaws.",
            )
        )

    # 6. If no high/medium issues, emit TLS_VALID (INFO, weight=0)
    has_high_or_medium = any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings)
    if not has_high_or_medium:
        findings.append(
            Finding(
                id="TLS_VALID",
                check="tls",
                title="TLS certificate is valid",
                severity=Severity.INFO,
                evidence=f"Issuer: {_get_issuer_name(cert)}; Expires: {cert.not_valid_after_utc.isoformat()}; SANs: {', '.join(sans) if sans else (cn or 'none')}",
                source="tls_certificate_analysis",
                confidence=0.9,
                weight=0,
                impact="Encrypted transport only; a valid TLS certificate does NOT prove a website is legitimate or safe.",
                recommendation="Continue to verify site legitimacy through other means (brand, reputation, content)",
            )
        )

    return findings


def _fetch_certificate_sync(hostname: str, port: int, timeout: float) -> tuple[cryptography.x509.Certificate, bool]:
    """
    Fetch peer certificate synchronously (for use in asyncio.to_thread).

    Returns:
        Tuple of (certificate, verified_chain)
    """
    # First try with default verification
    verified_chain = True
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # We'll verify hostname ourselves
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = cryptography.x509.load_der_x509_certificate(der_cert)
                return cert, verified_chain
    except ssl.SSLError:
        verified_chain = False
    except Exception:
        verified_chain = False

    # Fallback: no verification
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            cert = cryptography.x509.load_der_x509_certificate(der_cert)
            return cert, verified_chain


async def run(
    target: NormalisedUrl,
    resolved_ip: str | None = None,
    timeout: float = 4.0,
) -> tuple[list[Finding], CheckStatus]:
    """
    Run TLS certificate analysis on a normalised URL.

    Args:
        target: NormalisedUrl to analyze
        resolved_ip: Optional resolved IP from safefetch (for SSRF guard)
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (findings, check_status)
    """
    # Skip if not HTTPS
    if target.scheme != "https":
        return [], CheckStatus(
            check="tls",
            ran=False,
            reason="Target URL does not use HTTPS",
        )

    # SSRF guard: check resolved IP
    if resolved_ip is not None:
        if not is_ip_allowed(resolved_ip):
            return [], CheckStatus(
                check="tls",
                ran=False,
                reason="Blocked non-public IP for TLS inspection",
            )

    # SSRF guard: check target host if it's an IP literal
    if target.is_ip:
        if not is_ip_allowed(target.host):
            return [], CheckStatus(
                check="tls",
                ran=False,
                reason="Blocked non-public IP for TLS inspection",
            )

    # Determine host and port
    hostname = target.host
    port = target.port or 443

    try:
        # Fetch certificate in background thread
        cert, verified_chain = await asyncio.to_thread(
            _fetch_certificate_sync,
            hostname,
            port,
            timeout,
        )

        # Inspect certificate
        findings = inspect_certificate(cert, hostname, verified_chain)

        return findings, CheckStatus(check="tls", ran=True, reason=None)

    except socket.timeout:
        return [], CheckStatus(
            check="tls",
            ran=False,
            reason=f"TLS connection timeout after {timeout}s",
        )
    except ssl.SSLError as e:
        return [], CheckStatus(
            check="tls",
            ran=False,
            reason=f"TLS handshake failed: {e}",
        )
    except OSError as e:
        return [], CheckStatus(
            check="tls",
            ran=False,
            reason=f"Network error: {e}",
        )
    except Exception as e:
        return [], CheckStatus(
            check="tls",
            ran=False,
            reason=f"Unexpected error during TLS inspection: {e}",
        )