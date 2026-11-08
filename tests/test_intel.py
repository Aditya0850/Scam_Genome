"""Tests for trustlens.checks.intel."""

import httpx
import pytest

from trustlens.checks.intel import _check_local_feed, run
from trustlens.checks.normalise import normalise_url
from trustlens.config import Settings
from trustlens.models import Severity


def _urlhaus_transport(response_data: dict, status_code: int = 200) -> httpx.MockTransport:
    """Create a mock transport for URLhaus API."""
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(
            status_code,
            json=response_data,
            headers={"content-type": "application/json"},
        )

    transport = httpx.MockTransport(handler)
    transport.requests = requests  # type: ignore[attr-defined]
    return transport


@pytest.mark.asyncio
async def test_local_feed_url_match() -> None:
    target = normalise_url("http://evil-phishtank-verify.xyz/login")
    findings, status = await run(target, Settings(offline_mode=True))
    assert status.ran is True
    assert status.check == "intel"
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "TI_CRITICAL_FEED_MATCH"
    assert f.severity is Severity.CRITICAL
    assert f.weight == 100
    assert f.confidence == 0.98
    assert f.source == "local_threat_intel_feed"
    assert "evil-phishtank-verify.xyz/login" in f.evidence
    assert f.impact is not None
    assert f.recommendation is not None


@pytest.mark.asyncio
async def test_local_feed_host_match() -> None:
    target = normalise_url("http://evil-phishtank-verify.xyz/other")
    findings, status = await run(target, Settings(offline_mode=True))
    assert status.ran is True
    assert len(findings) == 1
    assert findings[0].id == "TI_CRITICAL_FEED_MATCH"
    assert "evil-phishtank-verify.xyz" in findings[0].evidence


@pytest.mark.asyncio
async def test_local_feed_registrable_domain_match() -> None:
    target = normalise_url("http://sub.metamask-airdrop-claim.icu/path")
    findings, status = await run(target, Settings(offline_mode=True))
    assert status.ran is True
    assert len(findings) == 1
    assert findings[0].id == "TI_CRITICAL_FEED_MATCH"
    assert "metamask-airdrop-claim.icu" in findings[0].evidence


@pytest.mark.asyncio
async def test_local_feed_no_match() -> None:
    target = normalise_url("http://example.com/")
    findings, status = await run(target, Settings(offline_mode=True))
    assert status.ran is True
    assert findings == []


@pytest.mark.asyncio
async def test_urlhaus_match_online_mode() -> None:
    settings = Settings(offline_mode=False, urlhaus_api_key="test-key")
    transport = _urlhaus_transport({"query_status": "ok", "urls": [{"url": "http://evil.com/malware"}]})

    target = normalise_url("http://suspicious.example.com/")
    findings, status = await run(target, settings, transport)

    assert status.ran is True
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "TI_CRITICAL_URLHAUS"
    assert f.severity is Severity.CRITICAL
    assert f.weight == 100
    assert f.confidence == 0.95
    assert f.source == "urlhaus"
    assert "suspicious.example.com" in f.evidence
    assert len(transport.requests) == 1  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_urlhaus_no_match() -> None:
    settings = Settings(offline_mode=False, urlhaus_api_key="test-key")
    transport = _urlhaus_transport({"query_status": "ok", "urls": []})

    target = normalise_url("http://clean.example.com/")
    findings, status = await run(target, settings, transport)

    assert status.ran is True
    assert findings == []
    assert len(transport.requests) == 1  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_urlhaus_query_status_not_ok() -> None:
    settings = Settings(offline_mode=False, urlhaus_api_key="test-key")
    transport = _urlhaus_transport({"query_status": "no_results"})

    target = normalise_url("http://unknown.example.com/")
    findings, status = await run(target, settings, transport)

    assert status.ran is True
    assert findings == []
    assert len(transport.requests) == 1  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_urlhaus_skipped_in_offline_mode() -> None:
    settings = Settings(offline_mode=True, urlhaus_api_key="test-key")
    transport = _urlhaus_transport({"query_status": "ok", "urls": [{"url": "http://evil.com/malware"}]})

    target = normalise_url("http://suspicious.example.com/")
    findings, status = await run(target, settings, transport)

    assert status.ran is True
    assert findings == []
    # URLhaus should not have been called
    assert len(transport.requests) == 0  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_urlhaus_skipped_without_api_key() -> None:
    settings = Settings(offline_mode=False, urlhaus_api_key="")
    transport = _urlhaus_transport({"query_status": "ok", "urls": [{"url": "http://evil.com/malware"}]})

    target = normalise_url("http://suspicious.example.com/")
    findings, status = await run(target, settings, transport)

    assert status.ran is True
    assert findings == []
    assert len(transport.requests) == 0  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_local_feed_checked_first() -> None:
    """Local feed should be checked before URLhaus, and URLhaus skipped on local match."""
    settings = Settings(offline_mode=False, urlhaus_api_key="test-key")
    transport = _urlhaus_transport({"query_status": "ok", "urls": [{"url": "http://evil.com/malware"}]})

    # This URL is in local feed
    target = normalise_url("http://evil-phishtank-verify.xyz/login")
    findings, status = await run(target, settings, transport)

    assert len(findings) == 1
    assert findings[0].source == "local_threat_intel_feed"
    # URLhaus should not have been called
    assert len(transport.requests) == 0  # type: ignore[attr-defined]


def test_check_local_feed_directly() -> None:
    target = normalise_url("http://hdfc-netbanking-verify.click/login")
    result = _check_local_feed(target)
    assert result is not None
    assert result.id == "TI_CRITICAL_FEED_MATCH"
    assert "hdfc-netbanking-verify.click" in result.evidence

    target2 = normalise_url("http://clean.example.com/")
    assert _check_local_feed(target2) is None