"""
TrustLens Threat Intelligence Check

Checks URLs/domains against local threat feed and URLhaus API.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from trustlens.checks.normalise import NormalisedUrl
from trustlens.config import Settings, get_settings
from trustlens.models import CheckStatus, Finding, Severity


# Local threat feed path
_THREAT_FEED_PATH = Path(__file__).resolve().parents[3] / "data" / "threat_feed.json"
_THREAT_FEED_CACHE: dict[str, Any] | None = None


def _load_threat_feed() -> dict[str, Any]:
    """Load local threat feed from JSON file."""
    global _THREAT_FEED_CACHE
    if _THREAT_FEED_CACHE is not None:
        return _THREAT_FEED_CACHE

    with open(_THREAT_FEED_PATH, "r", encoding="utf-8") as f:
        _THREAT_FEED_CACHE = json.load(f)

    return _THREAT_FEED_CACHE


def _check_local_feed(target: NormalisedUrl) -> Finding | None:
    """Check if target matches any indicator in local threat feed."""
    feed = _load_threat_feed()

    # Check exact URL match
    if target.normalized in feed.get("urls", []):
        return Finding(
            id="TI_CRITICAL_FEED_MATCH",
            check="intel",
            title="URL matches local threat intelligence feed",
            severity=Severity.CRITICAL,
            evidence=f"Matched URL in local feed: {target.normalized}",
            source="local_threat_intel_feed",
            confidence=0.98,
            weight=100,
            impact="This URL is a known phishing/malware indicator",
            recommendation="Block and do not interact with this URL",
        )

    # Check host match
    if target.host in feed.get("domains", []):
        return Finding(
            id="TI_CRITICAL_FEED_MATCH",
            check="intel",
            title="Host matches local threat intelligence feed",
            severity=Severity.CRITICAL,
            evidence=f"Matched host in local feed: {target.host}",
            source="local_threat_intel_feed",
            confidence=0.98,
            weight=100,
            impact="This host is a known phishing/malware indicator",
            recommendation="Block and do not interact with this host",
        )

    # Check registrable domain match
    if target.registrable_domain in feed.get("domains", []):
        return Finding(
            id="TI_CRITICAL_FEED_MATCH",
            check="intel",
            title="Registrable domain matches local threat intelligence feed",
            severity=Severity.CRITICAL,
            evidence=f"Matched registrable domain in local feed: {target.registrable_domain}",
            source="local_threat_intel_feed",
            confidence=0.98,
            weight=100,
            impact="This domain is a known phishing/malware indicator",
            recommendation="Block and do not interact with this domain",
        )

    return None


async def _query_urlhaus(host: str, api_key: str, transport: httpx.AsyncBaseTransport | None = None) -> Finding | None:
    """Query URLhaus API for host reputation."""
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    headers = {"Auth-Key": api_key} if api_key else {}
    payload = {"host": host}

    if transport is not None:
        client = httpx.AsyncClient(transport=transport, timeout=3.0)
    else:
        client = httpx.AsyncClient(timeout=3.0)

    try:
        response = await client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") == "ok" and data.get("urls"):
            return Finding(
                id="TI_CRITICAL_URLHAUS",
                check="intel",
                title="Host found in URLhaus threat database",
                severity=Severity.CRITICAL,
                evidence=f"URLhaus returned {len(data['urls'])} malicious URLs for host: {host}",
                source="urlhaus",
                confidence=0.95,
                weight=100,
                impact="This host is associated with malware distribution or phishing",
                recommendation="Block and do not interact with this host",
            )
    except httpx.HTTPError:
        pass
    except Exception:
        pass
    finally:
        await client.aclose()

    return None


async def run(
    target: NormalisedUrl,
    settings: Settings | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[list[Finding], CheckStatus]:
    """
    Run threat intelligence check on a normalised URL.

    Args:
        target: NormalisedUrl to check
        settings: Optional settings (uses cached settings if not provided)
        transport: Optional custom HTTP transport (for testing)

    Returns:
        Tuple of (findings, check_status)
    """
    findings: list[Finding] = []

    if settings is None:
        settings = get_settings()

    # 1. Check local threat feed
    local_match = _check_local_feed(target)
    if local_match:
        findings.append(local_match)
        return findings, CheckStatus(check="intel", ran=True, reason=None)

    # 2. Query URLhaus if not in offline mode and API key available
    if not settings.offline_mode and settings.urlhaus_api_key:
        urlhaus_match = await _query_urlhaus(target.host, settings.urlhaus_api_key, transport)
        if urlhaus_match:
            findings.append(urlhaus_match)

    return findings, CheckStatus(check="intel", ran=True, reason=None)