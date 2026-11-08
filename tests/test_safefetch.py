"""Tests for trustlens.checks.safefetch (SSRF guard and body limits)."""

import dns.resolver
import httpx
import pytest

from trustlens.checks.normalise import normalise_url
from trustlens.checks.safefetch import is_ip_allowed, run


class FakeResolver:
    """Canned DNS resolver: maps (host, type) to IPs, "NXDOMAIN", or NoAnswer."""

    def __init__(self, answers: dict[tuple[str, str], list[str] | str]) -> None:
        self.answers = answers

    async def resolve(self, host: str, record_type: str):
        result = self.answers.get((host, record_type))
        if result == "NXDOMAIN":
            raise dns.resolver.NXDOMAIN()
        if result is None:
            raise dns.resolver.NoAnswer()
        return result


def _html_transport(body: str = "<html>ok</html>") -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            content=body.encode(),
        )

    return httpx.MockTransport(handler)


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "10.0.0.1", "100.64.0.1"],
)
def test_is_ip_allowed_blocks_private_and_reserved(ip: str) -> None:
    assert is_ip_allowed(ip) is False


def test_is_ip_allowed_allows_public_address() -> None:
    assert is_ip_allowed("8.8.8.8") is True


async def test_public_host_with_only_a_records_is_fetched() -> None:
    resolver = FakeResolver({("example.com", "A"): ["93.184.216.34"]})

    result = await run(
        normalise_url("http://example.com/"),
        transport=_html_transport(),
        resolver=resolver,
    )

    assert result.ok is True
    assert result.status.ran is True
    assert result.resolved_ip == "93.184.216.34"
    assert "ok" in result.body_preview


async def test_one_private_a_record_blocks_the_host() -> None:
    resolver = FakeResolver({("example.com", "A"): ["93.184.216.34", "10.0.0.1"]})

    result = await run(
        normalise_url("http://example.com/"),
        transport=_html_transport(),
        resolver=resolver,
    )

    assert result.ok is False
    assert result.status.ran is False
    assert [f.id for f in result.findings] == ["FETCH_SSRF_BLOCKED"]
    assert result.body_preview == ""


async def test_redirect_to_loopback_is_blocked_before_request() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})

    resolver = FakeResolver({("example.com", "A"): ["93.184.216.34"]})

    result = await run(
        normalise_url("http://example.com/"),
        transport=httpx.MockTransport(handler),
        resolver=resolver,
    )

    assert result.ok is False
    assert result.status.ran is False
    assert "FETCH_SSRF_BLOCKED" in [f.id for f in result.findings]
    # The blocked hop must never be requested.
    assert requested == ["http://example.com/"]


async def test_body_larger_than_64kb_is_capped() -> None:
    resolver = FakeResolver({("example.com", "A"): ["93.184.216.34"]})

    result = await run(
        normalise_url("http://example.com/"),
        transport=_html_transport(body="a" * 100_000),
        resolver=resolver,
    )

    assert result.ok is True
    assert len(result.body_preview) == 4096
    assert set(result.body_preview) == {"a"}


async def test_non_html_content_type_yields_no_preview() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "application/octet-stream"}, content=b"\x00" * 5000)

    resolver = FakeResolver({("example.com", "A"): ["93.184.216.34"]})

    result = await run(
        normalise_url("http://example.com/"),
        transport=httpx.MockTransport(handler),
        resolver=resolver,
    )

    assert result.ok is True
    assert result.body_preview == ""
    assert "FETCH_UNSAFE_CONTENT_TYPE" in [f.id for f in result.findings]


async def test_nxdomain_is_not_reported_as_ssrf() -> None:
    resolver = FakeResolver({("missing.example", "A"): "NXDOMAIN", ("missing.example", "AAAA"): "NXDOMAIN"})

    result = await run(
        normalise_url("http://missing.example/"),
        transport=_html_transport(),
        resolver=resolver,
    )

    assert result.ok is False
    assert result.status.ran is False
    assert "FETCH_SSRF_BLOCKED" not in [f.id for f in result.findings]
    assert result.findings == []
