"""TrustLens HTTP API."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from trustlens.db import get_report, list_reports
from trustlens.message.analyze import analyze_message
from trustlens.models import Assessment, MessageRequest, UrlRequest
from trustlens.pipeline import analyze_url_from_request

app = FastAPI(title="TrustLens API")


class HealthResponse(BaseModel):
    status: str = "ok"


class ReportListResponse(BaseModel):
    reports: list[dict]


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness/readiness probe."""
    return HealthResponse()


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