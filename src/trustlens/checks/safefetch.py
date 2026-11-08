"""
TrustLens Safe Fetch with SSRF Protection

Fetches URLs with comprehensive SSRF protection including DNS resolution validation,
IP allowlisting, redirect chain validation, and response size limits.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any

import httpx
import dns.asyncresolver
import dns.exception

from trustlens.checks.normalise import NormalisedUrl
from trustlens.models import CheckStatus, FetchResult, Finding, Severity


class SSRFBlockedError(ValueError):
    """Raised when a URL resolves to a restricted or private network address."""

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

    try:
        # Resolve A records (IPv4)
        ipv4_answers = await resolver.resolve(host, "A")
        ipv4_ips = [str(rdata) for rdata in ipv4_answers]

        # Resolve AAAA records (IPv6)
        ipv6_answers = await resolver.resolve(host, "AAAA")
        ipv6_ips = [str(rdata) for rdata in ipv6_answers]
    except dns.exception.DNSException as e:
        raise SSRFBlockedError(f"DNS resolution failed for {host}: {e}") from e

    all_ips = ipv4_ips + ipv6_ips

    if not all_ips:
        raise SSRFBlockedError(f"No IP addresses resolved for {host}")

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


async def _fetch_single(
    client: httpx.AsyncClient,
    url: str,
    config: FetchConfig,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> tuple[httpx.Response, list[str], str]:
    """
    Perform a single HTTP request with DNS validation.

    Returns:
        Tuple of (response, resolved_ips, final_url)
    """
    # Parse URL to get host
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        raise SSRFBlockedError("No hostname in URL")

    # Resolve and validate DNS
    # We need to check if host is IP
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    resolved_ips = await resolve_and_validate(host, is_ip, resolver)

    # Make request with redirect following disabled
    response = await client.request(
        "GET",
        url,
        headers=config.headers,
        follow_redirects=False,
        timeout=config.timeout,
    )

    # Read limited body
    body = b""
    async for chunk in response.aiter_bytes():
        body += chunk
        if len(body) >= config.max_body_read:
            body = body[: config.max_body_read]
            break

    return response, resolved_ips, str(response.url)


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
    final_response: httpx.Response | None = None
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
            response, resolved_ips, response_url = await _fetch_single(client, current_url, config, resolver)

            redirect_chain.append(current_url)
            final_resolved_ips = resolved_ips
            final_url = response_url
            final_response = response

            # Check for redirect
            if response.is_redirect and hop < config.max_redirects:
                location = response.headers.get("location")
                if not location:
                    break

                # Resolve redirect URL
                from urllib.parse import urljoin

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

                # Validate redirect target DNS
                try:
                    is_ip = False
                    try:
                        ipaddress.ip_address(next_host)
                        is_ip = True
                    except ValueError:
                        pass
                    await resolve_and_validate(next_host, is_ip, resolver)
                except SSRFBlockedError as e:
                    all_findings.append(
                        Finding(
                            id="FETCH_REDIRECT_SSRF_BLOCKED",
                            check="safefetch",
                            title="Redirect blocked: resolves to restricted address",
                            severity=Severity.HIGH,
                            evidence=f"Redirect to {next_url} blocked: {e}",
                            source="safefetch_ssrf_guard",
                            confidence=1.0,
                            weight=0,
                        )
                    )
                    break

                current_url = next_url
                continue

            # Not a redirect or max redirects reached
            break

        # Build result
        if final_response is not None:
            # Create body preview
            body_bytes = b""
            async for chunk in final_response.aiter_bytes():
                body_bytes += chunk
                if len(body_bytes) >= config.max_body_read:
                    body_bytes = body_bytes[: config.max_body_read]
                    break

            body_preview = body_bytes[: config.max_body_preview].decode("utf-8", errors="replace")

            # Check content type
            content_type = final_response.headers.get("content-type", "").lower()
            allowed_types = ("text/html", "application/json", "text/plain", "application/xml", "text/xml")
            if not any(content_type.startswith(t) for t in allowed_types):
                all_findings.append(
                    Finding(
                        id="FETCH_UNSAFE_CONTENT_TYPE",
                        check="safefetch",
                        title=f"Potentially unsafe content type: {content_type}",
                        severity=Severity.LOW,
                        evidence=f"Response content-type: {content_type}",
                        source="safefetch_content_type_check",
                        confidence=0.5,
                        weight=0,
                    )
                )

            return FetchResult(
                ok=True,
                final_url=final_url,
                resolved_ip=final_resolved_ips[0] if final_resolved_ips else None,
                status_code=final_response.status_code,
                headers=dict(final_response.headers),
                redirect_chain=redirect_chain,
                body_preview=body_preview,
                findings=all_findings,
                status=CheckStatus(check="safefetch", ran=True, reason=None),
            )
        else:
            return FetchResult(
                ok=False,
                findings=all_findings,
                status=CheckStatus(check="safefetch", ran=False, reason="No response received"),
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