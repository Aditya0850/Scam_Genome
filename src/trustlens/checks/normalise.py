"""
TrustLens URL Normalisation

Handles URL parsing, IDNA encoding, PSL extraction, and validation.
Zero network calls during PSL extraction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

import idna
import tldextract


class NormalisationError(ValueError):
    """Raised when URL normalisation fails."""

    pass


@dataclass(frozen=True, slots=True)
class NormalisedUrl:
    """Normalised URL components."""

    original: str
    scheme: str
    host: str
    unicode_host: str
    port: int | None
    path: str
    query: str
    normalized: str
    registrable_domain: str
    suffix: str
    is_ip: bool
    has_userinfo: bool


# Pre-configured TLDExtract with zero network calls
EXTRA_SUFFIXES = ("bank.in",)
_tld_extract = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    extra_suffixes=EXTRA_SUFFIXES,
)


# Character validation
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
BACKSLASH_RE = re.compile(r"\\")
WHITESPACE_RE = re.compile(r"\s")

# IPv4 forms. Only a strict dotted quad is accepted as an IPv4 literal;
# numeric spellings such as 0177.0.0.1, 0x7f.1 and 2130706433 are rejected.
IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
NUMERIC_HOST_RE = re.compile(
    r"^(?:0[xX][0-9a-fA-F]+|\d+)(?:\.(?:0[xX][0-9a-fA-F]+|\d+))*\.?$"
)

# Input without "://" is only schemeless when it is host[:port] optionally
# followed by a path, query or fragment; anything else is a real URI scheme.
SCHEMELESS_RE = re.compile(
    r"^(?:\[[0-9A-Fa-f:.]+\]|[^\s:/?#@\[\]]+)(?::\d+)?(?:[/?#]|$)"
)

# Default ports
DEFAULT_PORTS = {"http": 80, "https": 443}

# Valid schemes
VALID_SCHEMES = {"http", "https"}


def _strip_control_chars(s: str) -> str:
    """Remove control characters and backslashes (whitespace is rejected, not removed)."""
    s = CONTROL_CHARS_RE.sub("", s)
    s = BACKSLASH_RE.sub("", s)
    return s


def _validate_host(host: str) -> None:
    """Validate host for forbidden characters."""
    if CONTROL_CHARS_RE.search(host) or BACKSLASH_RE.search(host) or WHITESPACE_RE.search(host):
        raise NormalisationError("Host contains invalid characters")


def _is_canonical_ipv4(host: str) -> bool:
    """Check for a strict dotted-quad IPv4 address (no octal, hex or leading zeros)."""
    match = IPV4_RE.match(host)
    if not match:
        return False
    parts = match.groups()
    if any(len(part) > 1 and part.startswith("0") for part in parts):
        return False
    return all(int(part) <= 255 for part in parts)


def _is_ip_address(host: str) -> bool:
    """Check if host is an IP literal (canonical IPv4 or IPv6)."""
    if ":" in host:
        return host.count(":") >= 2
    return _is_canonical_ipv4(host)


def _reject_ambiguous_numeric_host(host: str) -> None:
    """Reject non-standard IPv4 spellings (octal, hex, decimal-integer, short forms)."""
    if _is_ip_address(host):
        return
    if NUMERIC_HOST_RE.match(host):
        raise NormalisationError(f"Invalid or non-canonical numeric host: {host}")


def _parse_port(port_str: str) -> int:
    """Parse and range-check a port (1-65535)."""
    if not (port_str.isascii() and port_str.isdigit()):
        raise NormalisationError(f"Invalid port: {port_str!r}")
    port = int(port_str)
    if not 1 <= port <= 65535:
        raise NormalisationError(f"Port out of range: {port}")
    return port


def normalise_url(url: str) -> NormalisedUrl:
    """
    Normalise a URL into its components.

    Args:
        url: Raw URL string (may be schemeless)

    Returns:
        NormalisedUrl with all components extracted

    Raises:
        NormalisationError: If URL is invalid or uses unsupported scheme
    """
    if not url or not url.strip():
        raise NormalisationError("Empty URL")

    original = url

    # Surrounding whitespace is stripped; whitespace inside the URL is rejected,
    # never silently removed: "exa mple.com" must not collapse into "example.com".
    url = url.strip()
    if WHITESPACE_RE.search(url):
        raise NormalisationError("URL contains whitespace")

    url = _strip_control_chars(url)
    if not url:
        raise NormalisationError("Empty URL")

    # An explicit scheme requires "://". Without it the input is schemeless only
    # when it is host[:port][/?#...], so "paypa1.com:8080/login" is host:port
    # while "mailto:user@example.com" is an unsupported scheme.
    if "://" in url:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in VALID_SCHEMES:
            raise NormalisationError(
                f"Unsupported scheme: {scheme}. Only http/https allowed"
            )
    else:
        if not SCHEMELESS_RE.match(url):
            candidate = urlparse(url).scheme
            if candidate and candidate not in VALID_SCHEMES:
                raise NormalisationError(
                    f"Unsupported scheme: {candidate}. Only http/https allowed"
                )
            raise NormalisationError("Invalid URL: expected host or host:port")
        parsed = urlparse("http://" + url)
        scheme = "http"

    # Extract host and port
    netloc = parsed.netloc

    # Userinfo is everything before the last "@"; the host always follows it.
    has_userinfo = "@" in netloc
    if has_userinfo:
        netloc = netloc.rsplit("@", 1)[-1]

    host = netloc
    port: int | None = None

    if host.startswith("["):
        # IPv6 address
        end = host.find("]")
        if end == -1:
            raise NormalisationError("Invalid IPv6 address format")
        host, remainder = host[1:end], host[end + 1 :]
        if remainder:
            if not remainder.startswith(":"):
                raise NormalisationError("Invalid IPv6 address format")
            port = _parse_port(remainder[1:])
    elif ":" in host:
        # IPv4 or hostname with a port
        host, port_str = host.rsplit(":", 1)
        port = _parse_port(port_str)

    if not host:
        raise NormalisationError("Missing host")

    _validate_host(host)
    _reject_ambiguous_numeric_host(host)

    # IP literals must bypass IDNA: it rejects the ":" in IPv6 addresses.
    is_ip = _is_ip_address(host)
    if is_ip:
        ascii_host = host.lower()
    else:
        try:
            ascii_host = idna.encode(host, uts46=True).decode("ascii")
        except idna.IDNAError as e:
            raise NormalisationError(f"Invalid hostname: {e}") from e

    # Use tldextract for registrable domain
    extracted = _tld_extract(ascii_host)
    registrable_domain = extracted.registered_domain
    suffix = extracted.suffix

    # Build normalized URL
    # Strip default ports
    if port == DEFAULT_PORTS.get(scheme):
        port = None

    # IPv6 literals must be re-bracketed in the authority component
    normalized_netloc = f"[{ascii_host}]" if is_ip and ":" in ascii_host else ascii_host
    if port:
        normalized_netloc += f":{port}"

    # Userinfo and fragment are dropped from the normalized form
    normalized = urlunparse(
        (
            scheme,
            normalized_netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            "",
        )
    )

    return NormalisedUrl(
        original=original,
        scheme=scheme,
        host=ascii_host,
        unicode_host=host,
        port=port,
        path=parsed.path or "/",
        query=parsed.query,
        normalized=normalized,
        registrable_domain=registrable_domain,
        suffix=suffix,
        is_ip=is_ip,
        has_userinfo=has_userinfo,
    )


def normalise_urls(urls: list[str]) -> list[NormalisedUrl]:
    """Normalise multiple URLs, skipping invalid ones."""
    results = []
    for url in urls:
        try:
            results.append(normalise_url(url))
        except NormalisationError:
            continue
    return results