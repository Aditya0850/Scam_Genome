"""TrustLens pipeline: end-to-end URL assessment orchestration."""

from __future__ import annotations

from typing import Any

import dns.asyncresolver
import httpx

from trustlens.checks.headers import run as headers_run
from trustlens.checks.intel import run as intel_run
from trustlens.checks.lexical import run as lexical_run
from trustlens.checks.normalise import NormalisationError, normalise_url
from trustlens.checks.safefetch import run as safefetch_run
from trustlens.models import Assessment, CheckStatus, Finding, UrlRequest
from trustlens.scoring import build_assessment


def _has_ti_critical(finding: Finding) -> bool:
    """Check if finding is a TI_CRITICAL* finding."""
    return finding.id.startswith("TI_CRITICAL")


async def analyze_url(
    raw: str,
    *,
    safefetch_transport: httpx.AsyncBaseTransport | None = None,
    safefetch_resolver: dns.asyncresolver.Resolver | None = None,
    intel_transport: httpx.AsyncBaseTransport | None = None,
    _settings: Any = None,
) -> Assessment:
    """Normalise a URL, run intel, lexical, safefetch, and headers checks, and score the result."""
    try:
        normal = normalise_url(raw)
    except NormalisationError as exc:
        return build_assessment(
            target=raw,
            findings=[],
            checks=[CheckStatus(check="normalise", ran=False, reason=str(exc))],
            kind="url",
        )

    # 1. Threat intelligence check (runs first, can skip live fetch)
    intel_findings, intel_status = await intel_run(normal, _settings, intel_transport)

    checks: list[CheckStatus] = [intel_status]
    findings: list[Finding] = list(intel_findings)

    # SAFETY RULE: If intel confirms malicious, skip live safefetch
    skip_safefetch = any(_has_ti_critical(f) for f in intel_findings)

    # 2. Lexical analysis
    lexical_findings, lexical_status = await lexical_run(normal, _settings)
    checks.append(lexical_status)
    findings.extend(lexical_findings)

    # 3. Safe fetch (skipped if TI_CRITICAL found)
    if skip_safefetch:
        safefetch_status = CheckStatus(
            check="safefetch",
            ran=False,
            reason="Skipped live fetch for confirmed malicious target",
        )
        fetch_result = None
    else:
        fetch_result = await safefetch_run(
            normal,
            settings=_settings,
            transport=safefetch_transport,
            resolver=safefetch_resolver,
        )
        safefetch_status = fetch_result.status
        findings.extend(fetch_result.findings)

    checks.append(safefetch_status)

    # 4. Headers analysis (only if fetch succeeded)
    if fetch_result is not None:
        header_findings, header_status = headers_run(normal, fetch_result)
        findings.extend(header_findings)
        checks.append(header_status)
    else:
        header_status = CheckStatus(
            check="headers",
            ran=False,
            reason="Skipped: no fetch response available",
        )
        checks.append(header_status)

    return build_assessment(
        target=raw,
        findings=findings,
        checks=checks,
        kind="url",
    )


async def analyze_url_from_request(request: UrlRequest) -> Assessment:
    """Thin adapter: assess the URL carried by a UrlRequest."""
    return await analyze_url(request.url)