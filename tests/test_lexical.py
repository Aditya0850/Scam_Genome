"""Tests for trustlens.checks.lexical."""

import pytest

from trustlens.checks.lexical import run
from trustlens.checks.normalise import normalise_url
from trustlens.models import Severity


async def _findings(url: str):
    findings, status = await run(normalise_url(url))
    assert status.check == "lexical"
    assert status.ran is True
    return findings


async def _ids(url: str) -> list[str]:
    return [f.id for f in await _findings(url)]


async def test_typosquat_in_sld() -> None:
    findings = await _findings("paypa1.com/login")
    typo = next(f for f in findings if f.id == "LEX_TYPOSQUAT")
    assert typo.severity is Severity.HIGH
    assert typo.weight == 40


async def test_typosquat_with_www_subdomain() -> None:
    assert "LEX_TYPOSQUAT" in await _ids("www.paypa1.com")


async def test_exact_brand_label_in_subdomain() -> None:
    findings = await _findings("sbi.co.in.kyc-update.xyz")
    ids = [f.id for f in findings]
    assert "LEX_BRAND_SUBDOMAIN" in ids
    # Three labels sit left of kyc-update.xyz.
    assert "LEX_DEEP_SUBDOMAIN" in ids
    subdomain = next(f for f in findings if f.id == "LEX_BRAND_SUBDOMAIN")
    assert subdomain.severity is Severity.HIGH
    assert "sbi" in subdomain.evidence


async def test_userinfo_at_sign_is_flagged() -> None:
    findings = await _findings("https://google.com@evil.xyz")
    at_sign = next(f for f in findings if f.id == "LEX_USERINFO_AT")
    assert at_sign.severity is Severity.HIGH


async def test_mixed_script_punycode_host() -> None:
    # Cyrillic "а" + Greek "ρρ" + ASCII "le" -> xn--le-obca76c.com
    ids = await _ids("https://аρρle.com")
    assert "LEX_IDN_PUNYCODE" in ids
    assert "LEX_MIXED_SCRIPT" in ids


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/login",
        "https://sbi.co.in",
        "https://adamasuniversity.ac.in",
        "https://www.google.com",
        "https://accounts.google.com/signin",
        "https://netflix.com/login",
        "evil.com/accounting",
    ],
)
async def test_no_findings_for_legitimate_urls(url: str) -> None:
    assert await _ids(url) == []
