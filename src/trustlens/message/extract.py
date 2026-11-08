"""
TrustLens Message Content Extraction

Extracts and refangs URLs, emails, phone numbers, and UPI IDs from messages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class ExtractedURL:
    """Extracted and refanged URL."""

    original: str
    refanged: str
    normalized: str | None = None
    source_context: str = ""


@dataclass(frozen=True, slots=True)
class ExtractedEmail:
    """Extracted email address."""

    original: str
    refanged: str
    local_part: str
    domain: str
    source_context: str = ""


@dataclass(frozen=True, slots=True)
class ExtractedPhone:
    """Extracted phone number."""

    original: str
    normalized: str
    country_code: str | None = None
    source_context: str = ""


@dataclass(frozen=True, slots=True)
class ExtractedUPI:
    """Extracted UPI ID."""

    original: str
    handle: str
    bank: str
    source_context: str = ""


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    """Complete extraction result."""

    urls: list[ExtractedURL]
    emails: list[ExtractedEmail]
    phones: list[ExtractedPhone]
    upi_ids: list[ExtractedUPI]


# Regex patterns for extraction

# URL patterns (including obfuscated)
URL_PATTERN = re.compile(
    r"""
    (?:
        # Standard URLs
        https?://[^\s<>"{}|\\^`\[\]]+
        |
        # www. URLs
        www\.[^\s<>"{}|\\^`\[\]]+
        |
        # Obfuscated: hxxp, hxxps
        hxxps?://[^\s<>"{}|\\^`\[\]]+
        |
        # Obfuscated: [.] instead of .
        (?:https?://|www\.)?[^\s<>"{}|\\^`\[\]]+\[.\][^\s<>"{}|\\^`\[\]]+
        |
        # Obfuscated: (.) instead of .
        (?:https?://|www\.)?[^\s<>"{}|\\^`\[\]]+\(\.\)[^\s<>"{}|\\^`\[\]]+
        |
        # Obfuscated: hxxp with [.]
        hxxps?://[^\s<>"{}|\\^`\[\]]+\[.\][^\s<>"{}|\\^`\[\]]+
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Email patterns (including obfuscated)
EMAIL_PATTERN = re.compile(
    r"""
    (?:
        # Standard email
        [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
        |
        # Obfuscated: [at], (at), @
        [a-zA-Z0-9._%+-]+\s*(?:\[at\]|\(at\)|\sat\s)\s*[a-zA-Z0-9.-]+\s*(?:\.|\[dot\]|\(dot\))\s*[a-zA-Z]{2,}
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Phone patterns (Indian and international)
PHONE_PATTERN = re.compile(
    r"""
    (?:
        # Indian mobile: +91, 91, 0 prefix
        (?:\+91|91|0)?[6-9]\d{9}
        |
        # International: +CC or 00CC
        (?:\+|00)\d{1,3}\s?\d{6,14}
        |
        # Landline with STD code
        0\d{2,4}[-\s]?\d{6,8}
    )
    """,
    re.VERBOSE,
)

# UPI ID pattern: handle@bank
UPI_PATTERN = re.compile(
    r"""
    \b
    [a-zA-Z0-9._-]{1,64}
    @
    [a-zA-Z]{2,32}
    \b
    """,
    re.VERBOSE,
)

# Known UPI banks/handles for validation
UPI_BANKS = {
    "upi",
    "paytm",
    "phonepe",
    "gpay",
    "googlepay",
    "amazonpay",
    "whatsapppay",
    "whatsapp",
    "bhim",
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "kotak",
    "pnb",
    "bob",
    "canara",
    "union",
    "indian",
    "ioba",
    "cbi",
    "idbi",
    "federal",
    "karnataka",
    "kbl",
    "kvb",
    "lvb",
    "rbl",
    "yes",
    "idfc",
    "bandhan",
    "equitas",
    "ujjivan",
    "esaf",
    "fincare",
    "suryoday",
    "utkarsh",
    "north",
    "south",
    "central",
    "maharashtra",
    "gujarat",
    "punjab",
    "rajasthan",
    "haryana",
    "himachal",
    "jammu",
    "kashmir",
    "bihar",
    "jharkhand",
    "odisha",
    "westbengal",
    "assam",
    "northeast",
    "baroda",
    "mahila",
    "cooperative",
    "coop",
    "bank",
    "bk",
    "bnk",
    "money",
    "cash",
    "wallet",
    "pay",
    "upi",
}


def _refang_url(url: str) -> str:
    """Refang obfuscated URLs."""
    # hxxp -> http
    url = re.sub(r"^hxxp", "http", url, flags=re.IGNORECASE)
    url = re.sub(r"^hxxps", "https", url, flags=re.IGNORECASE)

    # [.] -> .
    url = url.replace("[.]", ".")

    # (.) -> .
    url = url.replace("(.)", ".")

    # [dot] -> .
    url = re.sub(r"\[dot\]", ".", url, flags=re.IGNORECASE)

    # (dot) -> .
    url = re.sub(r"\(dot\)", ".", url, flags=re.IGNORECASE)

    # Ensure scheme
    if not re.match(r"^[a-zA-Z]+://", url):
        if url.startswith("www."):
            url = "http://" + url
        else:
            url = "http://" + url

    return url


def _refang_email(email: str) -> str:
    """Refang obfuscated emails."""
    # [at] -> @
    email = re.sub(r"\[at\]", "@", email, flags=re.IGNORECASE)

    # (at) -> @
    email = re.sub(r"\(at\)", "@", email, flags=re.IGNORECASE)

    # " at " -> @
    email = re.sub(r"\s+at\s+", "@", email, flags=re.IGNORECASE)

    # [dot] -> .
    email = re.sub(r"\[dot\]", ".", email, flags=re.IGNORECASE)

    # (dot) -> .
    email = re.sub(r"\(dot\)", ".", email, flags=re.IGNORECASE)

    # " dot " -> .
    email = re.sub(r"\s+dot\s+", ".", email, flags=re.IGNORECASE)

    return email


def _normalize_phone(phone: str) -> tuple[str, str | None]:
    """Normalize phone number to E.164 format."""
    # Remove all non-digits except leading +
    cleaned = re.sub(r"[^\d+]", "", phone)

    # Handle 00 prefix (international)
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]

    # Handle Indian numbers
    if cleaned.startswith("+91"):
        return cleaned, "IN"
    if cleaned.startswith("91") and len(cleaned) == 12:
        return "+" + cleaned, "IN"
    if cleaned.startswith("0") and len(cleaned) == 11 and cleaned[1] in "6789":
        return "+91" + cleaned[1:], "IN"

    # Try to detect country code
    if cleaned.startswith("+"):
        # Extract country code (1-3 digits)
        match = re.match(r"^\+(\d{1,3})", cleaned)
        if match:
            return cleaned, match.group(1)

    return cleaned, None


def _is_valid_upi_bank(bank: str) -> bool:
    """Check if UPI bank suffix is known."""
    return bank.lower() in UPI_BANKS


def _looks_like_email(local: str, domain: str) -> bool:
    """Check if handle@bank looks like an email address."""
    # Common email domains
    email_domains = {
        "gmail",
        "yahoo",
        "hotmail",
        "outlook",
        "live",
        "msn",
        "aol",
        "icloud",
        "me",
        "mac",
        "protonmail",
        "proton",
        "zoho",
        "yandex",
        "mail",
        "inbox",
        "fastmail",
        "tutanota",
        "pm",
    }
    domain_lower = domain.lower()
    return domain_lower in email_domains or "." in domain_lower


def extract_urls(text: str, max_urls: int = 50) -> list[ExtractedURL]:
    """Extract and refang URLs from text."""
    urls = []
    seen = set()

    for match in URL_PATTERN.finditer(text):
        original = match.group(0)
        if original in seen:
            continue
        seen.add(original)

        refanged = _refang_url(original)

        # Validate it's a plausible URL
        try:
            parsed = urlparse(refanged)
            if parsed.netloc:
                normalized = refanged  # Will be normalized later by normalise.py
                urls.append(
                    ExtractedURL(
                        original=original,
                        refanged=refanged,
                        normalized=normalized,
                        source_context=text[max(0, match.start() - 50) : match.end() + 50],
                    )
                )
        except Exception:
            pass

        if len(urls) >= max_urls:
            break

    return urls


def extract_emails(text: str, max_emails: int = 50) -> list[ExtractedEmail]:
    """Extract and refang emails from text."""
    emails = []
    seen = set()

    for match in EMAIL_PATTERN.finditer(text):
        original = match.group(0)
        if original in seen:
            continue
        seen.add(original)

        refanged = _refang_email(original)

        # Validate email format
        if "@" in refanged:
            local, domain = refanged.split("@", 1)
            if "." in domain and len(local) > 0 and len(domain) > 3:
                emails.append(
                    ExtractedEmail(
                        original=original,
                        refanged=refanged,
                        local_part=local,
                        domain=domain,
                        source_context=text[max(0, match.start() - 50) : match.end() + 50],
                    )
                )

        if len(emails) >= max_emails:
            break

    return emails


def extract_phones(text: str, max_phones: int = 20) -> list[ExtractedPhone]:
    """Extract phone numbers from text."""
    phones = []
    seen = set()

    for match in PHONE_PATTERN.finditer(text):
        original = match.group(0)
        if original in seen:
            continue
        seen.add(original)

        normalized, country = _normalize_phone(original)

        phones.append(
            ExtractedPhone(
                original=original,
                normalized=normalized,
                country_code=country,
                source_context=text[max(0, match.start() - 50) : match.end() + 50],
            )
        )

        if len(phones) >= max_phones:
            break

    return phones


def extract_upi_ids(text: str, max_upi: int = 20) -> list[ExtractedUPI]:
    """Extract UPI IDs from text, distinguishing from emails."""
    upi_ids = []
    seen = set()

    for match in UPI_PATTERN.finditer(text):
        original = match.group(0)
        if original in seen:
            continue
        seen.add(original)

        if "@" not in original:
            continue

        handle, bank = original.split("@", 1)

        # Distinguish from email: UPI banks don't have dots, emails do
        if _looks_like_email(handle, bank):
            continue

        # Validate bank is known or looks like a bank code
        if not _is_valid_upi_bank(bank) and "." not in bank:
            # Could still be valid, but lower confidence
            pass

        upi_ids.append(
            ExtractedUPI(
                original=original,
                handle=handle,
                bank=bank,
                source_context=text[max(0, match.start() - 50) : match.end() + 50],
            )
        )

        if len(upi_ids) >= max_upi:
            break

    return upi_ids


def extract_all(text: str) -> ExtractionResult:
    """
    Extract all indicators from message text.

    Args:
        text: Message text to analyze

    Returns:
        ExtractionResult with deduplicated findings
    """
    if not text or not text.strip():
        return ExtractionResult(urls=[], emails=[], phones=[], upi_ids=[])

    # Cap text length
    text = text[:10000]

    urls = extract_urls(text)
    emails = extract_emails(text)
    phones = extract_phones(text)
    upi_ids = extract_upi_ids(text)

    # Deduplicate by refanged/normalized value
    seen_urls = set()
    deduped_urls = []
    for u in urls:
        key = u.refanged.lower()
        if key not in seen_urls:
            seen_urls.add(key)
            deduped_urls.append(u)

    seen_emails = set()
    deduped_emails = []
    for e in emails:
        key = e.refanged.lower()
        if key not in seen_emails:
            seen_emails.add(key)
            deduped_emails.append(e)

    seen_phones = set()
    deduped_phones = []
    for p in phones:
        key = p.normalized
        if key not in seen_phones:
            seen_phones.add(key)
            deduped_phones.append(p)

    seen_upi = set()
    deduped_upi = []
    for u in upi_ids:
        key = u.original.lower()
        if key not in seen_upi:
            seen_upi.add(key)
            deduped_upi.append(u)

    return ExtractionResult(
        urls=deduped_urls,
        emails=deduped_emails,
        phones=deduped_phones,
        upi_ids=deduped_upi,
    )