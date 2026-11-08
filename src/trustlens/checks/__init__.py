"""
TrustLens Checks Package
"""

from trustlens.checks.lexical import run as lexical_run
from trustlens.checks.normalise import NormalisedUrl, NormalisationError, normalise_url, normalise_urls
from trustlens.checks.safefetch import SSRFBlockedError, run as safefetch_run

__all__ = [
    "NormalisedUrl",
    "NormalisationError",
    "SSRFBlockedError",
    "lexical_run",
    "normalise_url",
    "normalise_urls",
    "safefetch_run",
]