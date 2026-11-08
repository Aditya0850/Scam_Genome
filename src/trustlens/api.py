"""TrustLens HTTP API."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from trustlens.models import Assessment, UrlRequest
from trustlens.pipeline import analyze_url_from_request

app = FastAPI(title="TrustLens API")


class HealthResponse(BaseModel):
    status: str = "ok"


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness/readiness probe."""
    return HealthResponse()


@app.post("/api/check-url", response_model=Assessment)
async def check_url(request: UrlRequest) -> Assessment:
    """Assess a single URL and return the resulting assessment."""
    return await analyze_url_from_request(request)
