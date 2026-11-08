"""Tests for trustlens.checks.tls (offline certificate inspection)."""

import datetime
from unittest.mock import AsyncMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from trustlens.checks.normalise import normalise_url
from trustlens.checks.tls import inspect_certificate, run
from trustlens.models import CheckStatus, Severity


def _make_cert(
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
    sans: list[str] | None = None,
    cn: str | None = None,
    issuer_name: str = "Test CA",
    key_size: int = 2048,
    sig_alg: str = "sha256",
    self_signed: bool = False,
) -> x509.Certificate:
    """Generate a test certificate."""
    now = datetime.datetime.now(datetime.timezone.utc)
    if not_before is None:
        not_before = now - datetime.timedelta(days=1)
    if not_after is None:
        not_after = now + datetime.timedelta(days=365)

    # Generate key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    # Subject
    subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn or "test.example.com")]
    subject = x509.Name(subject_attrs)

    # Issuer
    if self_signed:
        issuer = subject
    else:
        issuer_attrs = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_name)]
        issuer = x509.Name(issuer_attrs)

    # Builder
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # Add SANs
    if sans:
        san_list = [x509.DNSName(san) for san in sans]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list), critical=False
        )

    # Sign
    if sig_alg == "sha1":
        hash_alg = hashes.SHA1()
    elif sig_alg == "md5":
        hash_alg = hashes.MD5()
    else:
        hash_alg = hashes.SHA256()

    cert = builder.sign(private_key, hash_alg)
    return cert


def test_inspect_valid_certificate() -> None:
    """Test that a valid certificate produces TLS_VALID (INFO, weight=0)."""
    cert = _make_cert(
        sans=["example.com", "www.example.com"],
        issuer_name="Let's Encrypt",
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=True)

    # Should have TLS_VALID
    valid_findings = [f for f in findings if f.id == "TLS_VALID"]
    assert len(valid_findings) == 1, f"Expected TLS_VALID, got findings: {[f.id for f in findings]}"
    f = valid_findings[0]
    assert f.severity is Severity.INFO
    assert f.weight == 0
    assert f.confidence == 0.9
    assert "Encrypted transport only" in f.impact
    assert "Let's Encrypt" in f.evidence

    # Should NOT have any HIGH/MEDIUM findings
    high_medium = [f for f in findings if f.severity in (Severity.HIGH, Severity.MEDIUM)]
    assert len(high_medium) == 0, f"Unexpected high/medium findings: {[f.id for f in high_medium]}"


def test_inspect_expired_certificate() -> None:
    """Test that an expired certificate produces TLS_CERT_EXPIRED (HIGH, weight=35)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = _make_cert(
        not_before=now - datetime.timedelta(days=365),
        not_after=now - datetime.timedelta(days=1),  # Expired yesterday
        sans=["example.com"],
        issuer_name="Let's Encrypt",
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=True)

    expired = [f for f in findings if f.id == "TLS_CERT_EXPIRED"]
    assert len(expired) == 1
    f = expired[0]
    assert f.severity is Severity.HIGH
    assert f.weight == 35
    assert f.confidence == 0.95
    assert "expired" in f.evidence.lower()
    assert f.impact is not None
    assert f.recommendation is not None


def test_inspect_not_yet_valid_certificate() -> None:
    """Test that a not-yet-valid certificate produces TLS_CERT_EXPIRED (HIGH, weight=35)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = _make_cert(
        not_before=now + datetime.timedelta(days=1),  # Valid tomorrow
        not_after=now + datetime.timedelta(days=365),
        sans=["example.com"],
        issuer_name="Let's Encrypt",
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=True)

    expired = [f for f in findings if f.id == "TLS_CERT_EXPIRED"]
    assert len(expired) == 1
    f = expired[0]
    assert f.severity is Severity.HIGH
    assert f.weight == 35
    assert "not valid before" in f.evidence.lower()


def test_inspect_hostname_mismatch_san() -> None:
    """Test SAN mismatch produces TLS_HOSTNAME_MISMATCH (HIGH, weight=35)."""
    cert = _make_cert(
        sans=["other.example.com"],
        issuer_name="Let's Encrypt",
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=True)

    mismatch = [f for f in findings if f.id == "TLS_HOSTNAME_MISMATCH"]
    assert len(mismatch) == 1
    f = mismatch[0]
    assert f.severity is Severity.HIGH
    assert f.weight == 35
    assert f.confidence == 0.95
    assert "example.com" in f.evidence
    assert "other.example.com" in f.evidence


def test_inspect_hostname_match_wildcard() -> None:
    """Test that wildcard SAN matches subdomain."""
    cert = _make_cert(
        sans=["*.example.com"],
        issuer_name="Let's Encrypt",
    )
    findings = inspect_certificate(cert, "www.example.com", verified_chain=True)

    mismatch = [f for f in findings if f.id == "TLS_HOSTNAME_MISMATCH"]
    assert len(mismatch) == 0, f"Unexpected mismatch: {[f.evidence for f in mismatch]}"

    # Should have TLS_VALID
    valid = [f for f in findings if f.id == "TLS_VALID"]
    assert len(valid) == 1


def test_inspect_hostname_match_cn_fallback() -> None:
    """Test CN fallback when no SANs present."""
    cert = _make_cert(
        sans=None,
        cn="example.com",
        issuer_name="Let's Encrypt",
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=True)

    mismatch = [f for f in findings if f.id == "TLS_HOSTNAME_MISMATCH"]
    assert len(mismatch) == 0


def test_inspect_self_signed_certificate() -> None:
    """Test self-signed certificate produces TLS_UNTRUSTED_ISSUER (HIGH, weight=35)."""
    cert = _make_cert(
        sans=["example.com"],
        issuer_name="Test CA",
        self_signed=True,
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=False)

    untrusted = [f for f in findings if f.id == "TLS_UNTRUSTED_ISSUER"]
    assert len(untrusted) == 1
    f = untrusted[0]
    assert f.severity is Severity.HIGH
    assert f.weight == 35
    assert f.confidence == 0.9


def test_inspect_unverified_chain() -> None:
    """Test unverified chain produces TLS_UNTRUSTED_ISSUER."""
    cert = _make_cert(
        sans=["example.com"],
        issuer_name="Unknown CA",
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=False)

    untrusted = [f for f in findings if f.id == "TLS_UNTRUSTED_ISSUER"]
    assert len(untrusted) == 1


def test_inspect_weak_rsa_1024() -> None:
    """Test 1024-bit RSA key produces TLS_WEAK_CRYPTO."""
    cert = _make_cert(
        sans=["example.com"],
        issuer_name="Legacy CA",
        key_size=1024,
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=True)

    weak = [f for f in findings if f.id == "TLS_WEAK_CRYPTO"]
    assert len(weak) == 1
    f = weak[0]
    assert f.severity is Severity.MEDIUM
    assert f.weight == 20
    assert "1024" in f.evidence


def test_inspect_distrusted_ca_emudhra() -> None:
    """Test eMudhra CA produces TLS_DISTRUSTED_CA (HIGH, weight=40)."""
    cert = _make_cert(
        sans=["example.com"],
        issuer_name="eMudhra Limited",
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=True)

    distrusted = [f for f in findings if f.id == "TLS_DISTRUSTED_CA"]
    assert len(distrusted) == 1
    f = distrusted[0]
    assert f.severity is Severity.HIGH
    assert f.weight == 40
    assert f.confidence == 0.85
    assert "emudhra" in f.evidence.lower()
    # Check recommendation mentions limitation
    assert "limitation" in f.recommendation.lower() or "lineage" in f.recommendation.lower()


def test_inspect_distrusted_ca_wosign() -> None:
    """Test WoSign CA produces TLS_DISTRUSTED_CA."""
    cert = _make_cert(
        sans=["example.com"],
        issuer_name="WoSign CA",
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=True)

    distrusted = [f for f in findings if f.id == "TLS_DISTRUSTED_CA"]
    assert len(distrusted) == 1


def test_inspect_distrusted_ca_trustcor() -> None:
    """Test TrustCor CA produces TLS_DISTRUSTED_CA."""
    cert = _make_cert(
        sans=["example.com"],
        issuer_name="TrustCor Systems",
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=True)

    distrusted = [f for f in findings if f.id == "TLS_DISTRUSTED_CA"]
    assert len(distrusted) == 1


def test_inspect_valid_certificate_weight_zero() -> None:
    """Verify TLS_VALID always has weight=0 per spec."""
    cert = _make_cert(sans=["example.com"], issuer_name="DigiCert")
    findings = inspect_certificate(cert, "example.com", verified_chain=True)

    valid = [f for f in findings if f.id == "TLS_VALID"]
    assert len(valid) == 1
    assert valid[0].weight == 0
    assert valid[0].severity is Severity.INFO


def test_inspect_multiple_issues_all_reported() -> None:
    """Test that multiple issues are all reported."""
    # Not self-signed so issuer_name is preserved
    cert = _make_cert(
        sans=["other.com"],
        issuer_name="eMudhra Limited",
        key_size=1024,
        self_signed=False,
    )
    findings = inspect_certificate(cert, "example.com", verified_chain=False)

    # Should have all 4 issue types (not expired, so no TLS_CERT_EXPIRED)
    ids = {f.id for f in findings}
    assert "TLS_HOSTNAME_MISMATCH" in ids
    assert "TLS_UNTRUSTED_ISSUER" in ids
    assert "TLS_WEAK_CRYPTO" in ids
    assert "TLS_DISTRUSTED_CA" in ids
    # Should NOT have TLS_VALID when issues exist
    assert "TLS_VALID" not in ids


@pytest.mark.asyncio
async def test_run_non_https_returns_not_ran() -> None:
    """Test that non-HTTPS URLs return ran=False."""
    target = normalise_url("http://example.com/")
    findings, status = await run(target)

    assert status.ran is False
    assert status.check == "tls"
    assert "does not use HTTPS" in status.reason
    assert findings == []


@pytest.mark.asyncio
async def test_run_blocks_private_ip() -> None:
    """Test that private IPs are blocked for TLS inspection."""
    # Create a NormalisedUrl for an IP address
    from trustlens.checks.normalise import NormalisedUrl

    target = NormalisedUrl(
        original="https://10.0.0.1/",
        scheme="https",
        host="10.0.0.1",
        unicode_host="10.0.0.1",
        port=443,
        path="/",
        query="",
        normalized="https://10.0.0.1/",
        registrable_domain="10.0.0.1",
        suffix="",
        is_ip=True,
        has_userinfo=False,
    )

    with patch("trustlens.checks.tls.is_ip_allowed", return_value=False):
        findings, status = await run(target)

    assert status.ran is False
    assert "Blocked non-public IP" in status.reason


@pytest.mark.asyncio
async def test_run_blocks_resolved_private_ip() -> None:
    """Test that resolved private IPs are blocked."""
    target = normalise_url("https://example.com/")

    with patch("trustlens.checks.tls.is_ip_allowed", return_value=False):
        findings, status = await run(target, resolved_ip="10.0.0.1")

    assert status.ran is False
    assert "Blocked non-public IP" in status.reason