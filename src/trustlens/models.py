"""
TrustLens Core Models - Frozen Contract

This module defines the immutable data contracts for the TrustLens engine.
All models use strict Pydantic validation with extra="forbid".
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Classification(str, Enum):
    """Final classification verdicts for URL/message assessment."""

    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    INCONCLUSIVE = "inconclusive"


class Severity(str, Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """A single security finding from a check."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    id: str = Field(min_length=1, description="Unique finding identifier")
    check: str = Field(min_length=1, description="Name of the check that produced this finding")
    title: str = Field(min_length=1, description="Human-readable title")
    severity: Severity
    evidence: str = Field(min_length=1, max_length=1000, description="Supporting evidence")
    source: str = Field(min_length=1, description="Source of the finding")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence score 0-1")
    weight: int = Field(default=0, ge=0, le=100, description="Weight contribution to score 0-100")
    impact: str | None = Field(default=None, description="Impact description")
    recommendation: str | None = Field(default=None, description="Remediation recommendation")


class CheckStatus(BaseModel):
    """Status of a single check execution."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    check: str = Field(min_length=1, description="Check name")
    ran: bool = Field(description="Whether the check executed")
    reason: str | None = Field(default=None, description="Reason if check didn't run")


class FetchResult(BaseModel):
    """Result of fetching a URL with security findings."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ok: bool = Field(description="Whether fetch succeeded")
    final_url: str | None = Field(default=None, description="Final URL after redirects")
    resolved_ip: str | None = Field(default=None, description="Resolved IP address")
    status_code: int | None = Field(default=None, description="HTTP status code")
    headers: dict[str, str] = Field(default_factory=dict, description="Response headers")
    redirect_chain: list[str] = Field(default_factory=list, description="Redirect chain")
    body_preview: str = Field(default="", max_length=4096, description="Body preview (max 4096 chars)")
    findings: list[Finding] = Field(default_factory=list, description="Security findings")
    status: CheckStatus = Field(description="Check execution status")


class Assessment(BaseModel):
    """Complete threat assessment for a URL or message."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    report_id: str | None = Field(default=None, description="Unique report identifier")
    kind: Literal["url", "message"] = Field(default="url", description="Assessment type")
    target: str = Field(description="Assessed target (URL or message)")
    classification: Classification
    score: int = Field(default=0, ge=0, le=100, description="Risk score 0-100")
    findings: list[Finding] = Field(default_factory=list, description="All findings")
    checks: list[CheckStatus] = Field(default_factory=list, description="Check execution statuses")
    coverage: float = Field(default=0.0, ge=0.0, le=1.0, description="Fraction of checks that ran")
    unavailable_checks: list[str] = Field(default_factory=list, description="Checks that couldn't run")
    explanation: str | None = Field(default=None, description="LLM-generated explanation")
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Absence of known threats is not proof a site is safe.",
            "A valid TLS certificate does not mean a site is legitimate.",
        ],
        description="Known limitations",
    )
    related_reports: list[dict] | None = Field(default=None, description="Campaign correlation reports")
    report_hash: str | None = Field(default=None, description="Hash of the report")
    tx_hash: str | None = Field(default=None, description="Blockchain transaction hash")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Assessment timestamp (UTC)",
    )


class UrlRequest(BaseModel):
    """Request model for URL assessment."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: str = Field(min_length=3, max_length=2048, description="URL to assess")


class MessageRequest(BaseModel):
    """Request model for message assessment."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    text: str = Field(min_length=1, max_length=10000, description="Message text to assess")