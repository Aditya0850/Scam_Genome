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

# Default ports
DEFAULT_PORTS = {"http": 80, "https": 443}

# Valid schemes
VALID_SCHEMES = {"http", "https"}


def _strip_control_chars(s: str) -> str:
    """Remove control characters, backslashes, and whitespace."""
    s = CONTROL_CHARS_RE.sub("", s)
    s = BACKSLASH_RE.sub("", s)
    s = WHITESPACE_RE.sub("", s)
    return s


def _validate_host(host: str) -> None:
    """Validate host for forbidden characters."""
    if CONTROL_CHARS_RE.search(host) or BACKSLASH_RE.search(host) or WHITESPACE_RE.search(host):
        raise NormalisationError("Host contains invalid characters")


def _is_ip_address(host: str) -> bool:
    """Check if host is an IP address (IPv4 or IPv6)."""
    # IPv4
    ipv4_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if ipv4_pattern.match(host):
        parts = host.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    # IPv6 (basic check)
    if ":" in host and host.count(":") >= 2:
        return True
    return False


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

    url = _strip_control_chars(url.strip())

    # Add scheme if missing (default to http)
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    if scheme not in VALID_SCHEMES:
        raise NormalisationError(f"Unsupported scheme: {scheme}. Only http/https allowed")

    # Extract host and port
    netloc = parsed.netloc

    # Check for userinfo (user:pass@host)
    has_userinfo = "@" in netloc and netloc.rfind("@") > netloc.find("]")
    if has_userinfo:
        # Remove userinfo for host parsing
        netloc = netloc.split("@")[-1]

    # Parse host and port
    host = netloc
    port = None

    if host.startswith("["):
        # IPv6 address
        end = host.find("]")
        if end == -1:
            raise NormalisationError("Invalid IPv6 address format")
        host = host[1:end]
        if ":" in host[end + 1 :]:
            port_str = host[end + 2 :]
            if port_str.isdigit():
                port = int(port_str)
    else:
        # IPv4 or hostname
        if ":" in host:
            host_part, port_part = host.rsplit(":", 1)
            if port_part.isdigit():
                host = host_part
                port = int(port_part)

    _validate_host(host)

    # IDNA encode host (UTS-46)
    try:
        ascii_host = idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError as e:
        raise NormalisationError(f"Invalid hostname: {e}") from e

    # Use tldextract for registrable domain
    extracted = _tld_extract(ascii_host)
    registrable_domain = extracted.registered_domain
    suffix = extracted.suffix

    # Determine if host is IP
    is_ip = _is_ip_address(host)

    # Build normalized URL
    # Strip default ports
    if port == DEFAULT_PORTS.get(scheme):
        port = None

    normalized_netloc = ascii_host
    if port:
        normalized_netloc += f":{port}"

    normalized = urlunparse(
        (
            scheme,
            normalized_netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )

    return NormalisedUrl(
        original=url,
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