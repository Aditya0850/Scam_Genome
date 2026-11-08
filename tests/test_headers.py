"""Tests for trustlens.checks.headers."""

from trustlens.checks.headers import run
from trustlens.checks.normalise import normalise_url
from trustlens.models import CheckStatus, FetchResult, Finding, Severity


def _fetch_result(
    ok: bool = True,
    final_url: str = "https://example.com/",
    headers: dict[str, str] | None = None,
    status_code: int = 200,
) -> FetchResult:
    """Create a FetchResult for testing."""
    if headers is None:
        headers = {}
    return FetchResult(
        ok=ok,
        final_url=final_url,
        resolved_ip="93.184.216.34",
        status_code=status_code,
        headers=headers,
        redirect_chain=[],
        body_preview="",
        findings=[],
        status=CheckStatus(check="safefetch", ran=True),
    )


def test_fetch_failed_returns_not_ran() -> None:
    target = normalise_url("http://example.com/")
    fetch = _fetch_result(ok=False)

    findings, status = run(target, fetch)

    assert status.ran is False
    assert status.check == "headers"
    assert status.reason == "HTTP fetch did not succeed"
    assert findings == []


def test_https_missing_hsts_flagged() -> None:
    target = normalise_url("https://example.com/")
    fetch = _fetch_result(headers={"content-type": "text/html"})

    findings, status = run(target, fetch)

    assert status.ran is True
    hsts = next((f for f in findings if f.id == "HDR_MISSING_HSTS"), None)
    assert hsts is not None
    assert hsts.severity is Severity.LOW
    assert hsts.weight == 5


def test_http_no_hsts_check() -> None:
    target = normalise_url("http://example.com/")
    fetch = _fetch_result(final_url="http://example.com/", headers={"content-type": "text/html"})

    findings, status = run(target, fetch)

    assert status.ran is True
    hsts = next((f for f in findings if f.id == "HDR_MISSING_HSTS"), None)
    assert hsts is None  # HSTS only checked for HTTPS


def test_missing_csp_flagged() -> None:
    target = normalise_url("https://example.com/")
    fetch = _fetch_result(headers={"strict-transport-security": "max-age=31536000"})

    findings, status = run(target, fetch)

    csp = next((f for f in findings if f.id == "HDR_MISSING_CSP"), None)
    assert csp is not None
    assert csp.severity is Severity.LOW
    assert csp.weight == 5


def test_missing_clickjack_protection_flagged() -> None:
    target = normalise_url("https://example.com/")
    fetch = _fetch_result(headers={
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
    })

    findings, status = run(target, fetch)

    clickjack = next((f for f in findings if f.id == "HDR_MISSING_CLICKJACK"), None)
    assert clickjack is not None
    assert clickjack.severity is Severity.LOW
    assert clickjack.weight == 5


def test_xfo_present_no_clickjack_finding() -> None:
    target = normalise_url("https://example.com/")
    fetch = _fetch_result(headers={
        "x-frame-options": "DENY",
    })

    findings, status = run(target, fetch)

    clickjack = next((f for f in findings if f.id == "HDR_MISSING_CLICKJACK"), None)
    assert clickjack is None


def test_csp_frame_ancestors_present_no_clickjack_finding() -> None:
    target = normalise_url("https://example.com/")
    fetch = _fetch_result(headers={
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    })

    findings, status = run(target, fetch)

    clickjack = next((f for f in findings if f.id == "HDR_MISSING_CLICKJACK"), None)
    assert clickjack is None


def test_missing_nosniff_flagged_as_info() -> None:
    target = normalise_url("https://example.com/")
    fetch = _fetch_result(headers={
        "x-content-type-options": "",
    })

    findings, status = run(target, fetch)

    nosniff = next((f for f in findings if f.id == "HDR_MISSING_NOSNIFF"), None)
    assert nosniff is not None
    assert nosniff.severity is Severity.INFO
    assert nosniff.weight == 0


def test_nosniff_present_no_finding() -> None:
    target = normalise_url("https://example.com/")
    fetch = _fetch_result(headers={
        "x-content-type-options": "nosniff",
    })

    findings, status = run(target, fetch)

    nosniff = next((f for f in findings if f.id == "HDR_MISSING_NOSNIFF"), None)
    assert nosniff is None


def test_case_insensitive_header_matching() -> None:
    target = normalise_url("https://example.com/")
    fetch = _fetch_result(headers={
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
    })

    findings, status = run(target, fetch)

    assert status.ran is True
    ids = {f.id for f in findings}
    assert "HDR_MISSING_HSTS" not in ids
    assert "HDR_MISSING_CSP" not in ids
    assert "HDR_MISSING_CLICKJACK" not in ids
    assert "HDR_MISSING_NOSNIFF" not in ids


def test_complete_secure_headers_no_findings() -> None:
    target = normalise_url("https://example.com/")
    fetch = _fetch_result(headers={
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
    })

    findings, status = run(target, fetch)

    assert status.ran is True
    assert findings == []


def test_finding_fields_populated() -> None:
    target = normalise_url("https://example.com/")
    fetch = _fetch_result(headers={})

    findings, status = run(target, fetch)

    for f in findings:
        assert f.id.startswith("HDR_")
        assert f.check == "headers"
        assert f.title
        assert f.severity in (Severity.LOW, Severity.INFO)
        assert f.evidence
        assert f.source == "headers_analysis"
        assert 0.0 <= f.confidence <= 1.0
        assert f.weight in (0, 5)
        assert f.impact is not None
        assert f.recommendation is not None