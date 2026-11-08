"""Tests for the frozen model contract in trustlens.models."""

import pytest
from pydantic import ValidationError

from trustlens.models import (
    Assessment,
    CheckStatus,
    Classification,
    FetchResult,
    Finding,
    MessageRequest,
    Severity,
    UrlRequest,
)


def _finding(**overrides: object) -> Finding:
    data: dict[str, object] = {
        "id": "LEX_IP_HOST",
        "check": "lexical",
        "title": "Host is a raw IP address",
        "severity": Severity.HIGH,
        "evidence": "host=1.2.3.4",
        "source": "lexical",
    }
    data.update(overrides)
    return Finding(**data)  # type: ignore[arg-type]


def test_finding_evidence_is_1_to_1000_chars() -> None:
    with pytest.raises(ValidationError):
        _finding(evidence="")
    assert len(_finding(evidence="x" * 1000).evidence) == 1000
    with pytest.raises(ValidationError):
        _finding(evidence="x" * 1001)


def test_finding_weight_is_0_to_100() -> None:
    assert _finding().weight == 0
    assert _finding(weight=100).weight == 100
    with pytest.raises(ValidationError):
        _finding(weight=101)
    with pytest.raises(ValidationError):
        _finding(weight=-1)


def test_finding_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        _finding(nonexistent_field="x")


def test_assessment_has_default_limitations() -> None:
    assessment = Assessment(target="http://example.com/", classification=Classification.LOW_RISK)
    assert assessment.limitations == [
        "Absence of known threats is not proof a site is safe.",
        "A valid TLS certificate does not mean a site is legitimate.",
    ]
    assert assessment.kind == "url"
    assert assessment.score == 0


def test_fetch_result_body_preview_is_capped_at_4096() -> None:
    status = CheckStatus(check="safefetch", ran=True)
    assert len(FetchResult(ok=True, status=status, body_preview="x" * 4096).body_preview) == 4096
    with pytest.raises(ValidationError):
        FetchResult(ok=True, status=status, body_preview="x" * 4097)


def test_fetch_result_requires_status() -> None:
    with pytest.raises(ValidationError):
        FetchResult(ok=True)


def test_url_request_length_bounds() -> None:
    with pytest.raises(ValidationError):
        UrlRequest(url="ab")
    assert UrlRequest(url="abc").url == "abc"
    assert len(UrlRequest(url="x" * 2048).url) == 2048
    with pytest.raises(ValidationError):
        UrlRequest(url="x" * 2049)


def test_message_request_length_bounds() -> None:
    with pytest.raises(ValidationError):
        MessageRequest(text="")
    assert MessageRequest(text="hi").text == "hi"
    assert len(MessageRequest(text="x" * 10000).text) == 10000
    with pytest.raises(ValidationError):
        MessageRequest(text="x" * 10001)
