"""Tests for the Wave 1 fixes in trustlens.checks.normalise."""

import pytest

from trustlens.checks.normalise import NormalisationError, normalise_url


# (1) IP literals bypass IDNA, so IPv6 (and its port) normalises


def test_ipv6_literal_normalises() -> None:
    result = normalise_url("http://[::1]/")
    assert result.is_ip is True
    assert result.host == "::1"
    assert result.normalized == "http://[::1]/"


def test_ipv6_literal_with_port_is_parsed() -> None:
    result = normalise_url("http://[::1]:8080/x")
    assert result.is_ip is True
    assert result.host == "::1"
    assert result.port == 8080
    assert result.normalized == "http://[::1]:8080/x"


def test_ipv4_mapped_ipv6_is_an_ip_literal() -> None:
    result = normalise_url("http://[::ffff:127.0.0.1]/")
    assert result.is_ip is True
    assert result.host == "::ffff:127.0.0.1"


def test_canonical_ipv4_is_an_ip_literal() -> None:
    result = normalise_url("http://127.0.0.1/")
    assert result.is_ip is True
    assert result.host == "127.0.0.1"


# (2) Scheme detection requires "://", so host:port is not read as a scheme


def test_schemeless_host_with_port_is_not_treated_as_a_scheme() -> None:
    result = normalise_url("paypa1.com:8080/login")
    assert result.scheme == "http"
    assert result.host == "paypa1.com"
    assert result.port == 8080
    assert result.path == "/login"
    assert result.normalized == "http://paypa1.com:8080/login"


def test_explicit_non_http_scheme_is_still_rejected() -> None:
    with pytest.raises(NormalisationError, match="Unsupported scheme"):
        normalise_url("ftp://example.com/file")


# (3) Whitespace is rejected rather than silently removed


@pytest.mark.parametrize(
    "url",
    [
        "http://exa mple.com/",
        "http://example.com/a b",
        "http://x .com",
    ],
)
def test_interior_whitespace_is_rejected(url: str) -> None:
    with pytest.raises(NormalisationError, match="whitespace"):
        normalise_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.com\\@good.com",
        "http://x.com/\x00",
        "http://x.com/\x1f",
    ],
)
def test_backslashes_and_control_chars_are_rejected(url: str) -> None:
    with pytest.raises(NormalisationError, match="control characters or backslashes"):
        normalise_url(url)


def test_surrounding_whitespace_is_stripped() -> None:
    result = normalise_url("  http://x.com  ")
    assert result.original == "  http://x.com  "
    assert result.normalized == "http://x.com/"


@pytest.mark.parametrize(
    "url",
    [
        "mailto:user@example.com",
        "javascript:alert(1)",
        "data:text/html,x",
        "tel:+911234567890",
    ],
)
def test_scheme_without_double_slash_is_an_unsupported_scheme(url: str) -> None:
    with pytest.raises(NormalisationError, match="Unsupported scheme"):
        normalise_url(url)


# (4) Ports outside 1-65535 are rejected


@pytest.mark.parametrize(
    "port", ["0", "65536", "99999", "abc"]
)
def test_invalid_port_is_rejected(port: str) -> None:
    with pytest.raises(NormalisationError, match="[Pp]ort"):
        normalise_url(f"http://example.com:{port}/")


@pytest.mark.parametrize("port", [1, 8080, 65535])
def test_port_in_range_is_kept(port: int) -> None:
    result = normalise_url(f"http://example.com:{port}/")
    assert result.port == port


# (5) Non-standard IPv4 spellings (octal, hex, decimal-integer) are rejected


@pytest.mark.parametrize(
    "host",
    [
        "0177.0.0.1",  # octal
        "0x7f.1",  # hex
        "2130706433",  # decimal integer
        "127.1",  # short form
        "1.2.3.4.5",  # too many parts
        "999.1.1.1",  # octet out of range
    ],
)
def test_non_standard_ipv4_form_is_rejected(host: str) -> None:
    with pytest.raises(NormalisationError, match="numeric host"):
        normalise_url(f"http://{host}/")


# (6) original is the caller's raw input; normalized drops userinfo and fragment


def test_original_is_raw_input_and_normalized_drops_userinfo_and_fragment() -> None:
    raw = "https://google.com@evil.xyz/p?q=1#frag"
    result = normalise_url(raw)
    assert result.original == raw
    assert result.has_userinfo is True
    assert result.host == "evil.xyz"
    assert result.normalized == "https://evil.xyz/p?q=1"
    assert "#" not in result.normalized
    assert "google.com" not in result.normalized


def test_original_keeps_schemeless_input_as_given() -> None:
    result = normalise_url("sbi.co.in")
    assert result.original == "sbi.co.in"
    assert result.normalized == "http://sbi.co.in/"


def test_default_port_is_stripped_from_normalized_url() -> None:
    result = normalise_url("https://example.com:443/a")
    assert result.port is None
    assert result.normalized == "https://example.com/a"
