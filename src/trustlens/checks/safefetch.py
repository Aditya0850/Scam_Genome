"""
TrustLens Safe Fetch with SSRF Protection

Fetches URLs with comprehensive SSRF protection including DNS resolution validation,
IP allowlisting, redirect chain validation, and response size limits.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from trustlens.checks.normalise import NormalisedUrl
from trustlens.models import CheckStatus, FetchResult, Finding, Severity


class SSRFBlockedError(ValueError):
    """Raised when a URL resolves to a restricted or private network address."""

    pass


class FetchResolutionError(ValueError):
    """Raised when DNS resolution fails (NXDOMAIN, timeout, no addresses).

    This is deliberately distinct from SSRFBlockedError: an unresolvable host is
    not a security block, so it must not produce an SSRF finding.
    """

    pass


# Blocked IP ranges
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("0.0.0.0/8"),  # Reserved
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved future
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("ff00::/8"),  # IPv6 multicast
    ipaddress.ip_network("::/128"),  # IPv6 unspecified
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6
]

# Specific blocked IPs
BLOCKED_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # Cloud metadata
    ipaddress.ip_address("::ffff:169.254.169.254"),  # IPv4-mapped cloud metadata
}

# Maximum redirect hops
MAX_REDIRECTS = 3

# Timeout and size limits
REQUEST_TIMEOUT = 5.0
MAX_BODY_READ = 64 * 1024  # 64KB
MAX_BODY_PREVIEW = 4096  # 4KB preview


def is_ip_allowed(ip_str: str) -> bool:
    """
    Check if an IP address is allowed (global, non-private, non-reserved).

    Args:
        ip_str: IP address string (IPv4 or IPv6)

    Returns:
        True if IP is allowed, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)

        # Unwrap IPv4-mapped IPv6 addresses
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped

        # Check if global
        if not ip.is_global:
            return False

        # Check against private/reserved ranges
        for network in PRIVATE_RANGES:
            if ip in network:
                return False

        # Check specific blocked IPs
        if ip in BLOCKED_IPS:
            return False

        return True
    except ValueError:
        return False


def _is_ip_literal(host: str) -> bool:
    """Check whether host is already an IP address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def resolve_and_validate(
    host: str, is_ip: bool, resolver: dns.asyncresolver.Resolver | None = None
) -> list[str]:
    """
    Resolve a hostname to IP addresses and validate they are allowed.

    Args:
        host: Hostname or IP address
        is_ip: Whether host is already an IP address
        resolver: Optional custom DNS resolver

    Returns:
        List of allowed IP addresses

    Raises:
        FetchResolutionError: If no addresses could be resolved
        SSRFBlockedError: If any resolved IP is not allowed
    """
    if is_ip:
        if not is_ip_allowed(host):
            raise SSRFBlockedError(f"IP address {host} is not allowed (private/reserved/blocked)")
        return [host]

    # Create resolver if not provided
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

    all_ips: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answers = await resolver.resolve(host, record_type)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # No records of this type is normal (many hosts are A-only).
            continue
        except dns.exception.DNSException as e:
            # Timeouts and server failures are not SSRF; report separately.
            raise FetchResolutionError(f"DNS resolution failed for {host}: {e}") from e
        all_ips.extend(str(rdata) for rdata in answers)

    if not all_ips:
        raise FetchResolutionError(f"No IP addresses resolved for {host}")

    # Validate all IPs - if ANY is not allowed, block
    for ip in all_ips:
        if not is_ip_allowed(ip):
            raise SSRFBlockedError(f"Host {host} resolves to restricted IP: {ip}")

    return all_ips


@dataclass
class FetchConfig:
    """Configuration for safe fetch."""

    timeout: float = REQUEST_TIMEOUT
    max_body_read: int = MAX_BODY_READ
    max_body_preview: int = MAX_BODY_PREVIEW
    max_redirects: int = MAX_REDIRECTS
    follow_redirects: bool = False
    headers: dict[str, str] | None = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {
                "User-Agent": "TrustLens/0.1.0 (+https://github.com/trustlens)",
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "close",
            }


@dataclass(frozen=True)
class _ResponseSnapshot:
    """Response data captured while the streamed connection is still open."""

    status_code: int
    headers: dict[str, str]
    url: str
    content_type: str
    body: bytes


def _content_type_allowed(content_type: str) -> bool:
    """Only text/html and JSON bodies are read."""
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type in {"text/html", "application/json"}


async def _read_limited_body(response: httpx.Response, config: FetchConfig) -> bytes:
    """Read at most max_body_read bytes from a streamed response."""
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) >= config.max_body_read:
            break
    return bytes(body[: config.max_body_read])


async def _fetch_single(
    client: httpx.AsyncClient,
    url: str,
    config: FetchConfig,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> tuple[_ResponseSnapshot, list[str]]:
    """
    Perform a single streamed HTTP request with DNS validation.

    Returns:
        Tuple of (response snapshot, resolved_ips)
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        raise SSRFBlockedError("No hostname in URL")

    resolved_ips = await resolve_and_validate(host, _is_ip_literal(host), resolver)

    # Streaming keeps the network read bounded; other content types are never read.
    async with client.stream(
        "GET",
        url,
        headers=config.headers,
        follow_redirects=False,
        timeout=config.timeout,
    ) as response:
        content_type = response.headers.get("content-type", "")
        body = (
            await _read_limited_body(response, config)
            if _content_type_allowed(content_type)
            else b""
        )
        snapshot = _ResponseSnapshot(
            status_code=response.status_code,
            headers=dict(response.headers),
            url=str(response.url),
            content_type=content_type,
            body=body,
        )

    return snapshot, resolved_ips


async def run(
    target: NormalisedUrl,
    settings: Any = None,
    transport: httpx.AsyncBaseTransport | None = None,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> FetchResult:
    """
    Safely fetch a URL with SSRF protection and redirect validation.

    Args:
        target: NormalisedUrl to fetch
        settings: Optional settings (unused but kept for interface consistency)
        transport: Optional custom HTTP transport (for testing)
        resolver: Optional custom DNS resolver (for testing)

    Returns:
        FetchResult with response data and any security findings
    """
    config = FetchConfig()
    redirect_chain: list[str] = []
    all_findings: list[Finding] = []
    final_snapshot: _ResponseSnapshot | None = None
    final_resolved_ips: list[str] = []
    final_url = target.normalized

    # Create client
    if transport is not None:
        client = httpx.AsyncClient(transport=transport, timeout=config.timeout)
    else:
        client = httpx.AsyncClient(timeout=config.timeout)

    try:
        current_url = target.normalized

        for hop in range(config.max_redirects + 1):
            # Fetch current URL
            snapshot, resolved_ips = await _fetch_single(client, current_url, config, resolver)

            redirect_chain.append(current_url)
            final_resolved_ips = resolved_ips
            final_url = snapshot.url
            final_snapshot = snapshot

            # Check for redirect
            if 300 <= snapshot.status_code < 400 and hop < config.max_redirects:
                location = snapshot.headers.get("location")
                if not location:
                    break

                # Resolve redirect URL
                next_url = urljoin(current_url, location)

                # Re-validate DNS for redirect target
                parsed = urlparse(next_url)
                next_host = parsed.hostname or ""
                if not next_host:
                    all_findings.append(
                        Finding(
                            id="FETCH_INVALID_REDIRECT",
                            check="safefetch",
                            title="Redirect to invalid URL",
                            severity=Severity.MEDIUM,
                            evidence=f"Redirect location has no hostname: {location}",
                            source="safefetch_redirect_validation",
                            confidence=0.8,
                            weight=0,
                        )
                    )
                    break

                # Re-validate the redirect target before requesting it. A blocked
                # target raises SSRFBlockedError, reported as FETCH_SSRF_BLOCKED.
                await resolve_and_validate(next_host, _is_ip_literal(next_host), resolver)

                current_url = next_url
                continue

            # Not a redirect or max redirects reached
            break

        # Build result
        if final_snapshot is None:
            return FetchResult(
                ok=False,
                findings=all_findings,
                status=CheckStatus(check="safefetch", ran=False, reason="No response received"),
            )

        # Non-html/json bodies are never read, so the preview stays empty.
        if not _content_type_allowed(final_snapshot.content_type):
            all_findings.append(
                Finding(
                    id="FETCH_UNSAFE_CONTENT_TYPE",
                    check="safefetch",
                    title=f"Potentially unsafe content type: {final_snapshot.content_type}",
                    severity=Severity.LOW,
                    evidence=f"Response content-type: {final_snapshot.content_type}",
                    source="safefetch_content_type_check",
                    confidence=0.5,
                    weight=0,
                )
            )

        return FetchResult(
            ok=True,
            final_url=final_url,
            resolved_ip=final_resolved_ips[0] if final_resolved_ips else None,
            status_code=final_snapshot.status_code,
            headers=final_snapshot.headers,
            redirect_chain=redirect_chain,
            body_preview=final_snapshot.body[: config.max_body_preview].decode(
                "utf-8", errors="replace"
            ),
            findings=all_findings,
            status=CheckStatus(check="safefetch", ran=True, reason=None),
        )

    except FetchResolutionError as e:
        # Unresolvable host: not an SSRF block, so no SSRF finding.
        return FetchResult(
            ok=False,
            findings=[],
            status=CheckStatus(check="safefetch", ran=False, reason=str(e)),
        )
    except SSRFBlockedError as e:
        return FetchResult(
            ok=False,
            findings=[
                Finding(
                    id="FETCH_SSRF_BLOCKED",
                    check="safefetch",
                    title="Target resolves to restricted or private network address",
                    severity=Severity.HIGH,
                    evidence=str(e),
                    source="safefetch_ssrf_guard",
                    confidence=1.0,
                    weight=0,
                )
            ],
            status=CheckStatus(check="safefetch", ran=False, reason=str(e)),
        )
    except httpx.TimeoutException as e:
        return FetchResult(
            ok=False,
            findings=[
                Finding(
                    id="FETCH_TIMEOUT",
                    check="safefetch",
                    title="Request timeout",
                    severity=Severity.MEDIUM,
                    evidence=f"Request timed out after {config.timeout}s: {e}",
                    source="safefetch_timeout",
                    confidence=0.9,
                    weight=0,
                )
            ],
            status=CheckStatus(check="safefetch", ran=False, reason=f"Timeout: {e}"),
        )
    except httpx.RequestError as e:
        return FetchResult(
            ok=False,
            findings=[
                Finding(
                    id="FETCH_REQUEST_ERROR",
                    check="safefetch",
                    title="Request failed",
                    severity=Severity.MEDIUM,
                    evidence=f"HTTP request error: {e}",
                    source="safefetch_request_error",
                    confidence=0.8,
                    weight=0,
                )
            ],
            status=CheckStatus(check="safefetch", ran=False, reason=f"Request error: {e}"),
        )
    except Exception as e:
        return FetchResult(
            ok=False,
            findings=[
                Finding(
                    id="FETCH_UNEXPECTED_ERROR",
                    check="safefetch",
                    title="Unexpected error during fetch",
                    severity=Severity.MEDIUM,
                    evidence=f"Error: {type(e).__name__}: {e}",
                    source="safefetch_unexpected",
                    confidence=0.5,
                    weight=0,
                )
            ],
            status=CheckStatus(check="safefetch", ran=False, reason=f"Unexpected error: {e}"),
        )
    finally:
        await client.aclose()