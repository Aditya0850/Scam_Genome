"""Tests for trustlens.scoring rule coverage."""

import time

import pytest

from trustlens.checks.safefetch import run as safefetch_run, SSRFBlockedError
from trustlens.models import CheckStatus, Classification, Finding, Severity
from trustlens.scoring import build_assessment


def _ti_critical() -> Finding:
    return Finding(
        id="TI_ONE",
        check="threatintel",
        title="Threat intel hit",
        severity=Severity.CRITICAL,
        evidence="matched",
        source="ti",
        weight=10,
    )


def _medium() -> Finding:
    return Finding(
        id="FLOW",
        check="lexical",
        title="Medium finding",
        severity=Severity.MEDIUM,
        evidence="x",
        source="lexical",
        weight=40,
    )


def _info() -> Finding:
    return Finding(
        id="INFO_ONLY",
        check="tls",
        title="Valid TLS",
        severity=Severity.INFO,
        evidence="ok",
        source="tls",
        weight=20,
    )


def test_score_caps_at_100() -> None:
    findings = [
        _medium(),
        Finding(id="X", check="x", title="x", severity=Severity.MEDIUM,
                evidence="x", source="x", weight=70),
    ]
    checks = [CheckStatus(check="lexical", ran=True)]
    a = build_assessment("http://x.com/", findings, checks)
    assert a.score == 100
    assert a.classification == Classification.HIGH_RISK


def test_info_severity_never_adds_to_score() -> None:
    a = build_assessment(
        "http://x.com/", [_info(), _medium()],
        [CheckStatus(check="x", ran=True)],
    )
    assert a.score == 40  # only the medium finding counts


def test_confirmed_malicious_only_with_ti_critical() -> None:
    # TI critical wins over any score.
    checks = [CheckStatus(check="lexical", ran=True),
              CheckStatus(check="safefetch", ran=True)]
    a = build_assessment("http://x.com/", [_medium(), _ti_critical()], checks)
    assert a.classification == Classification.CONFIRMED_MALICIOUS

    # A non-critical TI finding does not trigger confirmed_malicious.
    # Use a high-weight finding so score >= 60 -> HIGH_RISK (not confirmed_malicious).
    a2 = build_assessment(
        "http://x.com/", [
            Finding(id="TI_LOW", check="ti", title="x", severity=Severity.LOW,
                    evidence="x", source="ti", weight=5),
            Finding(id="HIGH_WEIGHT", check="lexical", title="x", severity=Severity.HIGH,
                    evidence="x", source="lexical", weight=60),
        ], checks,
    )
    assert a2.classification == Classification.HIGH_RISK


def test_coverage_below_half_lowers_risk_to_inconclusive() -> None:
    checks = [CheckStatus(check="lexical", ran=False),
              CheckStatus(check="safefetch", ran=False),
              CheckStatus(check="ti", ran=True)]
    # _medium() gives score 40 -> SUSPICIOUS; coverage 1/3 < 0.5 -> INCONCLUSIVE
    a = build_assessment("http://x.com/", [_medium()], checks)
    assert a.coverage == 1 / 3
    assert "lexical" in a.unavailable_checks
    assert "safefetch" in a.unavailable_checks
    assert a.classification == Classification.INCONCLUSIVE

    # High risk (score >= 60) with low coverage stays HIGH_RISK
    a_high = build_assessment(
        "http://x.com/",
        [Finding(id="HIGH", check="lexical", title="x", severity=Severity.HIGH,
                 evidence="x", source="lexical", weight=70)],
        checks,
    )
    assert a_high.coverage == 1 / 3
    assert a_high.classification == Classification.HIGH_RISK

    checks2 = [CheckStatus(check="lexical", ran=False),
               CheckStatus(check="safefetch", ran=True)]
    a2 = build_assessment("http://x.com/", [], checks2)
    assert a2.coverage == 0.5
    # coverage < 0.5 is strict; 0.5 exactly does not downgrade.
    assert a2.classification == Classification.LOW_RISK

    checks3 = [CheckStatus(check="lexical", ran=False),
               CheckStatus(check="safefetch", ran=False),
               CheckStatus(check="ti", ran=True)]
    a3 = build_assessment("http://x.com/", [], checks3)
    assert a3.coverage < 0.5
    assert a3.classification == Classification.INCONCLUSIVE


def test_timestamp_is_utc_now() -> None:
    before = int(time.time())
    a = build_assessment("http://x.com/", [], [CheckStatus(check="x", ran=True)])
    assert a.timestamp.tzinfo is not None
    assert abs((a.timestamp.timestamp() - before)) < 2


def test_report_fields_default_to_none() -> None:
    a = build_assessment("http://x.com/", [], [CheckStatus(check="x", ran=True)])
    assert a.explanation is None
    assert a.report_hash is None
    assert a.tx_hash is None
