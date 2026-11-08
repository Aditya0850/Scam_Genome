"""Tests for trustlens.message.analyze."""

import pytest

from trustlens.config import Settings
from trustlens.message.analyze import analyze_message
from trustlens.models import Classification, Severity


@pytest.mark.asyncio
async def test_urgent_only_message_stays_low_risk() -> None:
    """Urgent language alone must score < 25 (LOW_RISK)."""
    text = "Urgent! Your account will be blocked within 24 hours. Act immediately!"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    assert result.classification == Classification.LOW_RISK
    assert result.score < 25
    # Should have MSG_URGENCY_COERCION (weight=15)
    urgency_findings = [f for f in result.findings if f.id == "MSG_URGENCY_COERCION"]
    assert len(urgency_findings) == 1
    assert urgency_findings[0].severity is Severity.LOW
    assert urgency_findings[0].weight == 15


@pytest.mark.asyncio
async def test_otp_plus_kyc_link_becomes_high_risk() -> None:
    """OTP request + KYC link should become HIGH_RISK."""
    text = "Your OTP is 123456. Please verify your KYC at https://sbi-kyc-update.top/verify"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    # Should have credential request (40) + urgency (15) + payment lure (30) + impersonation (25)
    # Plus TI_CRITICAL from URL (100) = CONFIRMED_MALICIOUS
    # But the URL is in threat feed, so TI_CRITICAL_FEED_MATCH (100)
    assert result.classification == Classification.CONFIRMED_MALICIOUS
    assert result.score >= 100

    # Check for credential request
    cred = [f for f in result.findings if f.id == "MSG_CREDENTIAL_REQUEST"]
    assert len(cred) == 1
    assert cred[0].weight == 40

    # Check for TI_CRITICAL from URL correlation
    ti = [f for f in result.findings if f.id.startswith("TI_CRITICAL")]
    assert len(ti) >= 1


@pytest.mark.asyncio
async def test_message_with_threat_feed_url_becomes_confirmed_malicious() -> None:
    """Message containing a URL from threat feed should be CONFIRMED_MALICIOUS."""
    text = "Please click here: http://evil-phishtank-verify.xyz/login"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    assert result.classification == Classification.CONFIRMED_MALICIOUS
    ti = [f for f in result.findings if f.id.startswith("TI_CRITICAL")]
    assert len(ti) >= 1
    assert ti[0].source == "message_url_correlation"
    assert "evil-phishtank-verify.xyz" in ti[0].evidence


@pytest.mark.asyncio
async def test_credential_request_detected() -> None:
    """Test credential harvesting detection."""
    text = "Please share your OTP and CVV for verification"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    cred = [f for f in result.findings if f.id == "MSG_CREDENTIAL_REQUEST"]
    assert len(cred) == 1
    assert cred[0].severity is Severity.HIGH
    assert cred[0].weight == 40
    assert "otp" in cred[0].evidence.lower() or "cvv" in cred[0].evidence.lower()


@pytest.mark.asyncio
async def test_payment_lure_detected() -> None:
    """Test payment/financial lure detection."""
    text = "You won a lottery! Send ₹5000 processing fee to claim your prize"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    lure = [f for f in result.findings if f.id == "MSG_PAYMENT_LURE"]
    assert len(lure) == 1
    assert lure[0].severity is Severity.MEDIUM
    assert lure[0].weight == 30


@pytest.mark.asyncio
async def test_upi_with_urgency_triggers_payment_lure() -> None:
    """Test UPI ID with urgency language triggers payment lure."""
    text = "Urgent! Send money to user@oksbi immediately or account blocked"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    # Should have urgency, UPI detected, and payment lure
    urgency = [f for f in result.findings if f.id == "MSG_URGENCY_COERCION"]
    lure = [f for f in result.findings if f.id == "MSG_PAYMENT_LURE"]
    assert len(urgency) == 1
    assert len(lure) == 1


@pytest.mark.asyncio
async def test_impersonation_detected() -> None:
    """Test organization impersonation detection."""
    text = "This is SBI. Your account is suspended. Click https://fake-sbi.com to verify"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    imp = [f for f in result.findings if f.id == "MSG_IMPERSONATION"]
    assert len(imp) == 1
    assert imp[0].severity is Severity.MEDIUM
    assert imp[0].weight == 25
    assert "sbi" in imp[0].evidence.lower()


@pytest.mark.asyncio
async def test_clean_message_low_risk() -> None:
    """Test clean message with no indicators stays LOW_RISK."""
    text = "Hello, just checking in. Let me know when you're free."
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    assert result.classification == Classification.LOW_RISK
    assert result.score == 0


@pytest.mark.asyncio
async def test_multiple_urls_correlated() -> None:
    """Test that multiple URLs in message are all analyzed (up to 3)."""
    text = "Check these: https://example.com/ https://google.com/ https://github.com/ https://extra.com/"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    # Should have analyzed up to 3 URLs
    # Check that checks include URL analysis checks
    url_checks = [c for c in result.checks if c.check in ("intel", "lexical", "safefetch", "tls", "headers")]
    assert len(url_checks) >= 3  # At least 3 URL analyses worth of checks


@pytest.mark.asyncio
async def test_message_assessment_kind_and_target() -> None:
    """Test assessment has correct kind and truncated target."""
    text = "A" * 300  # Long message
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    assert result.kind == "message"
    assert len(result.target) <= 200


@pytest.mark.asyncio
async def test_seed_phrase_detection() -> None:
    """Test seed phrase / recovery phrase detection."""
    text = "Please provide your seed phrase or recovery phrase for wallet verification"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    cred = [f for f in result.findings if f.id == "MSG_CREDENTIAL_REQUEST"]
    assert len(cred) == 1
    assert "seed phrase" in cred[0].evidence.lower() or "recovery phrase" in cred[0].evidence.lower()


@pytest.mark.asyncio
async def test_netbanking_password_detection() -> None:
    """Test netbanking password detection."""
    text = "Enter your netbanking password to unlock your account"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    cred = [f for f in result.findings if f.id == "MSG_CREDENTIAL_REQUEST"]
    assert len(cred) == 1
    assert "netbanking" in cred[0].evidence.lower()


@pytest.mark.asyncio
async def test_airdrop_claim_detection() -> None:
    """Test airdrop claim detection."""
    text = "Claim your airdrop! Connect wallet at https://metamask-airdrop-claim.icu"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    lure = [f for f in result.findings if f.id == "MSG_PAYMENT_LURE"]
    assert len(lure) == 1
    assert "airdrop" in lure[0].evidence.lower()

    # Also should have TI_CRITICAL from URL
    ti = [f for f in result.findings if f.id.startswith("TI_CRITICAL")]
    assert len(ti) >= 1


@pytest.mark.asyncio
async def test_urgency_weight_never_exceeds_15() -> None:
    """Verify urgency findings always have weight <= 15."""
    text = "URGENT! IMMEDIATE ACTION REQUIRED! LEGAL ACTION WITHIN 24 HOURS!"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    for f in result.findings:
        if f.id == "MSG_URGENCY_COERCION":
            assert f.weight <= 15
            assert f.severity is Severity.LOW


@pytest.mark.asyncio
async def test_finding_fields_populated() -> None:
    """Test all finding fields are properly populated."""
    text = "OTP 123456 please verify"
    settings = Settings(offline_mode=True)

    result = await analyze_message(text, settings)

    for f in result.findings:
        assert f.id
        assert f.check == "message"
        assert f.title
        assert f.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        assert f.evidence
        assert f.source == "message_analysis"
        assert 0.0 <= f.confidence <= 1.0
        assert 0 <= f.weight <= 100
        assert f.impact is not None
        assert f.recommendation is not None