"""
TrustLens Message Package
"""

from trustlens.message.extract import (
    ExtractedEmail,
    ExtractedPhone,
    ExtractedUPI,
    ExtractedURL,
    ExtractionResult,
    extract_all,
    extract_emails,
    extract_phones,
    extract_upi_ids,
    extract_urls,
)

__all__ = [
    "ExtractedEmail",
    "ExtractedPhone",
    "ExtractedUPI",
    "ExtractedURL",
    "ExtractionResult",
    "extract_all",
    "extract_emails",
    "extract_phones",
    "extract_upi_ids",
    "extract_urls",
]