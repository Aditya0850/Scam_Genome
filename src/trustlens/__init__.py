"""
TrustLens - URL and Message Threat Classification Engine

A deterministic threat classification engine with LLM explainability.
"""

from trustlens.models import (
    Assessment,
    CheckStatus,
    Classification,
    Finding,
    FetchResult,
    MessageRequest,
    Severity,
    UrlRequest,
)

__version__ = "0.1.0"

__all__ = [
    "Assessment",
    "CheckStatus",
    "Classification",
    "Finding",
    "FetchResult",
    "MessageRequest",
    "Severity",
    "UrlRequest",
]