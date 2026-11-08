"""Tests for trustlens.pipeline orchestration."""

from __future__ import annotations

import httpx
import pytest

from trustlens.checks.normalise import normalise_url
from trustlens.checks.safefetch import run as safefetch_run, is_ip_allowed
from trustlens.models import CheckStatus, Classification, FetchResult
from trustlens.pipeline import analyze_url


def _html_transport(body: str = "<html>ok</html>") -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "text/html; charset=utf-8",
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
            },
            content=body.encode(),
        )
    return httpx.MockTransport(handler)


class FakeResolver:
    def __init__(self, answers: dict[tuple[str, str], list[str] | str]) -> None:
        self.answers = answers

    async def resolve(self, host: str, record_type: str):
        result = self.answers.get((host, record_type))
        if result == "NXDOMAIN":
            import dns.resolver
            raise dns.resolver.NXDOMAIN()
        if result is None:
            import dns.resolver
            raise dns.resolver.NoAnswer()
        return result


@pytest.mark.asyncio
async def test_normalisation_failure_yields_inconclusive():
    a = await analyze_url("   ")  # whitespace-only fails normalisation
    assert a.classification == Classification.INCONCLUSIVE
    assert a.checks == [CheckStatus(check="normalise", ran=False, reason="Empty URL")]
    assert a.coverage == 0.0
    assert a.unavailable_checks == ["normalise"]
    assert a.findings == []


@pytest.mark.asyncio
async def test_pipeline_runs_all_checks():
    resolver = FakeResolver({("example.com", "A"): ["93.184.216.34"]})
    result = await analyze_url(
        "https://example.com/",
        safefetch_transport=_html_transport(),
        safefetch_resolver=resolver,
    )
    assert result.classification == Classification.LOW_RISK
    assert result.score == 0  # clean public page with proper headers
    assert [c.check for c in result.checks] == ["intel", "lexical", "safefetch", "headers"]
    assert all(c.ran for c in result.checks)
    assert result.coverage == 1.0
    # safefetch status is carried into the assessment checks.
    assert isinstance(result.checks[2], CheckStatus)


@pytest.mark.asyncio
async def test_pipeline_collects_safefetch_findings():
    # A loopback A record blocks the host; safefetch does not run, so its
    # status has ran=False. Lexical runs clean. Score=0.
    # intel runs, lexical runs, safefetch blocked, headers skipped -> coverage = 2/4 = 0.5
    resolver = FakeResolver({("example.com", "A"): ["127.0.0.1"]})
    result = await analyze_url(
        "https://example.com/",
        safefetch_transport=_html_transport(),
        safefetch_resolver=resolver,
    )
    assert result.classification == Classification.LOW_RISK
    assert result.score == 0
    assert "safefetch" in result.unavailable_checks
    assert "headers" in result.unavailable_checks
    assert any(f.id == "FETCH_SSRF_BLOCKED" for f in result.findings)
    assert not any(c.ran for c in result.checks if c.check == "safefetch")
    assert not any(c.ran for c in result.checks if c.check == "headers")
    # Coverage: intel ran, lexical ran, safefetch not ran, headers not ran = 2/4 = 0.5
    assert result.coverage == 0.5
