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
from trustlens.checks.tls import run as tls_run
from trustlens.db import save_report
from trustlens.explain import generate_explanation
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
    save_to_db: bool = True,
    generate_explanation_flag: bool = True,
) -> Assessment:
    """Normalise a URL, run intel, lexical, safefetch, tls, and headers checks, and score the result."""
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

    # SAFETY RULE: If intel confirms malicious, skip live safefetch and tls
    skip_live_checks = any(_has_ti_critical(f) for f in intel_findings)

    # 2. Lexical analysis
    lexical_findings, lexical_status = await lexical_run(normal, _settings)
    checks.append(lexical_status)
    findings.extend(lexical_findings)

    # 3. Safe fetch (skipped if TI_CRITICAL found)
    if skip_live_checks:
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

    # 4. TLS analysis (skipped if TI_CRITICAL found or fetch failed/blocked)
    if skip_live_checks or fetch_result is None or not fetch_result.ok:
        tls_status = CheckStatus(
            check="tls",
            ran=False,
            reason="Skipped: no fetch response available" if fetch_result is None or not fetch_result.ok else "Skipped live TLS for confirmed malicious target",
        )
    else:
        tls_findings, tls_status = await tls_run(
            normal,
            resolved_ip=fetch_result.resolved_ip,
        )
        findings.extend(tls_findings)

    checks.append(tls_status)

    # 5. Headers analysis (only if fetch succeeded)
    if fetch_result is not None and fetch_result.ok:
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

    # Build assessment
    assessment = build_assessment(
        target=raw,
        findings=findings,
        checks=checks,
        kind="url",
    )

    # Extract registrable domain and resolved IP for correlation
    registrable_domain = normal.registrable_domain if normal.registrable_domain else None
    resolved_ip = fetch_result.resolved_ip if fetch_result and fetch_result.ok else None

    # Save to database and get campaign correlations
    if save_to_db:
        assessment = save_report(
            assessment,
            registrable_domain=registrable_domain,
            resolved_ip=resolved_ip,
        )

    # Generate explanation
    if generate_explanation_flag:
        assessment.explanation = await generate_explanation(assessment, _settings)

    return assessment


async def analyze_url_from_request(request: UrlRequest) -> Assessment:
    """Thin adapter: assess the URL carried by a UrlRequest."""
    return await analyze_url(request.url)