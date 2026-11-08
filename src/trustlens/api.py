"""TrustLens HTTP API."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from trustlens.chain import anchor_report, verify_on_chain
from trustlens.db import get_report, list_reports
from trustlens.message.analyze import analyze_message
from trustlens.models import Assessment, Finding, MessageRequest, UrlRequest
from trustlens.pipeline import analyze_url_from_request

app = FastAPI(title="TrustLens API")

# CORS middleware for frontend dev server access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class HealthResponse(BaseModel):
    status: str = "ok"


class ReportListResponse(BaseModel):
    reports: list[dict]


class AnchorResponse(BaseModel):
    tx_hash: str
    report_hash: str
    target_fingerprint: str
    mode: str
    contract_address: str | None = None
    block_number: int | None = None


class VerifyResponse(BaseModel):
    report_id: str
    stored_hash: str | None
    recomputed_hash: str
    on_chain_hash: str | None
    tx_hash: str | None
    target_fingerprint: str
    anchored: bool
    integrity_verified: bool
    provenance_note: str


# Frontend-compatible response models
class ScanUrlRequest(BaseModel):
    url: str


class ScanMessageRequest(BaseModel):
    message: str


class FindingFrontend(BaseModel):
    id: str
    check: str
    severity: str
    confidence: float
    evidence: str
    source: str


class ScanResponse(BaseModel):
    id: str
    target: str
    classification: str
    risk_score: int
    coverage: int
    timestamp: str
    findings: list[FindingFrontend]
    unavailable_checks: list[str]


class RegisterResponse(BaseModel):
    report_id: str
    tx_hash: str
    report_hash: str
    target_fingerprint: str
    mode: str
    contract_address: str | None = None
    block_number: int | None = None


class VerifyFrontendResponse(BaseModel):
    valid: bool
    message: str


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness/readiness probe."""
    return HealthResponse()


# --- Core backend endpoints ---
@app.post("/api/check-url", response_model=Assessment)
async def check_url(request: UrlRequest) -> Assessment:
    """Assess a single URL and return the resulting assessment."""
    return await analyze_url_from_request(request)


@app.post("/api/check-message", response_model=Assessment)
async def check_message(request: MessageRequest) -> Assessment:
    """Assess a message text and return the resulting assessment."""
    return await analyze_message(request.text)


@app.get("/api/reports", response_model=ReportListResponse)
async def get_reports(limit: int = 20) -> ReportListResponse:
    """List recent assessment reports."""
    reports = list_reports(limit=limit)
    return ReportListResponse(reports=reports)


@app.get("/api/reports/{report_id}", response_model=Assessment)
async def get_report_endpoint(report_id: str) -> Assessment:
    """Retrieve a specific report by ID."""
    report = get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.post("/api/reports/{report_id}/anchor", response_model=AnchorResponse)
async def anchor_report_endpoint(report_id: str) -> AnchorResponse:
    """Anchor a saved report on-chain / in local ledger."""
    report = get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    result = anchor_report(report)
    return AnchorResponse(**result)


# --- Frontend-compatible alias endpoints ---
def _assessment_to_scan_response(assessment: Assessment) -> ScanResponse:
    """Convert internal Assessment to frontend ScanResponse format."""
    return ScanResponse(
        id=assessment.report_id or "unknown",
        target=assessment.target,
        classification=assessment.classification.value.replace("_", " ").title(),
        risk_score=assessment.score,
        coverage=int(assessment.coverage * 100),
        timestamp=assessment.timestamp.isoformat(),
        findings=[
            FindingFrontend(
                id=f.id,
                check=f.check,
                severity=f.severity.value.title(),
                confidence=f.confidence,
                evidence=f.evidence,
                source=f.source,
            )
            for f in assessment.findings
        ],
        unavailable_checks=assessment.unavailable_checks,
    )


@app.post("/api/scan/url", response_model=ScanResponse)
async def scan_url_frontend(request: ScanUrlRequest) -> ScanResponse:
    """Frontend-compatible URL scan endpoint."""
    assessment = await analyze_url_from_request(UrlRequest(url=request.url))
    return _assessment_to_scan_response(assessment)


@app.post("/api/scan/message", response_model=ScanResponse)
async def scan_message_frontend(request: ScanMessageRequest) -> ScanResponse:
    """Frontend-compatible message scan endpoint."""
    assessment = await analyze_message(request.message)
    return _assessment_to_scan_response(assessment)


@app.post("/api/reports/{report_id}/register", response_model=RegisterResponse)
async def register_report_frontend(report_id: str) -> RegisterResponse:
    """Frontend-compatible report registration (alias for anchor)."""
    report = get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    result = anchor_report(report)
    return RegisterResponse(**result)


@app.get("/api/reports/{report_id}/verify", response_model=VerifyFrontendResponse)
async def verify_report_frontend(report_id: str) -> VerifyFrontendResponse:
    """Frontend-compatible verification endpoint."""
    report = get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    result = verify_on_chain(report_id)
    return VerifyFrontendResponse(
        valid=result["integrity_verified"],
        message="The recomputed report commitment was compared with the on-chain value."
        if result["anchored"]
        else "Report verified locally (not yet anchored on-chain). Hashes match.",
    )