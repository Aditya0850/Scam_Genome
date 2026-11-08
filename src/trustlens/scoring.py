"""TrustLens scoring: score, coverage, and classification decisions."""

from __future__ import annotations

from datetime import datetime, timezone

from trustlens.models import Assessment, CheckStatus, Classification, Finding, Severity


def build_assessment(
    target: str,
    findings: list[Finding],
    checks: list[CheckStatus],
    kind: str = "url",
) -> Assessment:
    """Build an Assessment from gathered findings and check statuses."""
    score = sum(f.weight for f in findings if f.severity != Severity.INFO)
    score = min(score, 100)

    total = len(checks) or 1
    ran = [c for c in checks if c.ran]
    coverage = len(ran) / total
    unavailable_checks = [c.check for c in checks if not c.ran]

    # Authoritative threat-intel signal takes precedence.
    has_ti_critical = any(
        f.id.startswith("TI_") and f.severity == Severity.CRITICAL for f in findings
    )
    if has_ti_critical:
        classification = Classification.CONFIRMED_MALICIOUS
    else:
        classification = _score_to_risk(score)

    # Low coverage downgrades low/suspicious verdicts to inconclusive.
    if coverage < 0.5 and classification in (Classification.LOW_RISK, Classification.SUSPICIOUS):
        classification = Classification.INCONCLUSIVE

    return Assessment(
        kind=kind if kind in ("url", "message") else "url",
        target=target,
        classification=classification,
        score=score,
        findings=findings,
        checks=checks,
        coverage=coverage,
        unavailable_checks=unavailable_checks,
        explanation=None,
        report_hash=None,
        tx_hash=None,
        timestamp=datetime.now(timezone.utc),
    )


def _score_to_risk(score: int) -> Classification:
    """Map a raw 0-100 score to a risk classification."""
    if score >= 60:
        return Classification.HIGH_RISK
    if score >= 30:
        return Classification.SUSPICIOUS
    return Classification.LOW_RISK
