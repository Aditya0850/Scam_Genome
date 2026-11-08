"""
TrustLens Lexical Analysis Check

Detects phishing indicators through URL structure analysis,
brand impersonation, typosquatting, and suspicious patterns.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rapidfuzz.distance import Levenshtein

from trustlens.checks.normalise import NormalisedUrl
from trustlens.models import CheckStatus, Finding, Severity


# Brand data loaded from JSON
_BRAND_DATA: dict[str, Any] | None = None
_BRAND_DOMAINS: set[str] = set()
_PROTECTED_SUFFIXES: set[str] = {"gov.in", "ac.in", "edu", "gov", "mil", "bank.in"}

# Leet character mappings for typo detection
LEET_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
}

# Multi-character leet patterns
MULTI_LEET = {
    "rn": "m",
    "vv": "w",
    "nn": "m",
    "vv": "w",
    "cl": "d",
    "oi": "a",
}


# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "zip",
    "mov",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "buzz",
    "icu",
    "work",
    "support",
    "loan",
    "download",
    "racing",
    "win",
    "party",
    "review",
    "country",
    "kim",
    "cricket",
    "science",
    "stream",
    "accountant",
    "date",
    "faith",
    "trade",
    "webcam",
}

# Lure keywords commonly used in phishing URLs
LURE_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "kyc",
    "update",
    "secure",
    "security",
    "account",
    "wallet",
    "suspend",
    "suspended",
    "refund",
    "unlock",
    "confirm",
    "confirmation",
    "validate",
    "validation",
    "authenticate",
    "authentication",
    "authorize",
    "authorization",
    "recover",
    "recovery",
    "reset",
    "verify-now",
    "verify-account",
    "account-update",
    "security-update",
    "urgent",
    "immediate",
    "action-required",
    "limited-time",
    "expire",
    "expiry",
    "alert",
    "notification",
    "notice",
    "warning",
}


def _load_brand_data() -> dict[str, Any]:
    """Load brand data from JSON file."""
    global _BRAND_DATA, _BRAND_DOMAINS
    if _BRAND_DATA is not None:
        return _BRAND_DATA

    brands_path = Path(__file__).parent.parent.parent / "data" / "brands.json"
    with open(brands_path, "r", encoding="utf-8") as f:
        _BRAND_DATA = json.load(f)

    # Build set of all official brand domains for fast lookup
    _BRAND_DOMAINS = set()
    for brand in _BRAND_DATA.get("brands", []):
        for domain in brand.get("official_domains", []):
            _BRAND_DOMAINS.add(domain.lower())

    # Add protected suffixes
    _PROTECTED_SUFFIXES.update(_BRAND_DATA.get("protected_suffixes", []))

    return _BRAND_DATA


def _get_brand_for_domain(domain: str) -> dict[str, Any] | None:
    """Find brand info for a given domain."""
    _load_brand_data()
    domain = domain.lower()
    for brand in _BRAND_DATA.get("brands", []):
        for official_domain in brand.get("official_domains", []):
            if domain == official_domain.lower() or domain.endswith("." + official_domain.lower()):
                return brand
    return None


def _is_protected_domain(registrable_domain: str, suffix: str) -> bool:
    """Check if domain is in protected list (official brands, gov, edu, etc.)."""
    if registrable_domain in _BRAND_DOMAINS:
        return True
    if suffix in _PROTECTED_SUFFIXES:
        return True
    return False


def _deleet(s: str) -> str:
    """Convert leet speak to normal characters."""
    result = []
    i = 0
    while i < len(s):
        # Check multi-char patterns first
        matched = False
        for pattern, replacement in MULTI_LEET.items():
            if s[i:].startswith(pattern):
                result.append(replacement)
                i += len(pattern)
                matched = True
                break
        if not matched:
            result.append(LEET_MAP.get(s[i], s[i]))
            i += 1
    return "".join(result)


def _extract_sld(host: str, registrable_domain: str) -> str:
    """Extract the second-level domain (SLD) from host."""
    if host == registrable_domain:
        return registrable_domain.split(".")[0]

    # Remove registrable domain suffix
    if host.endswith("." + registrable_domain):
        subdomain_part = host[: -len(registrable_domain) - 1]
        # SLD is the last part before registrable domain
        parts = subdomain_part.split(".")
        return parts[-1] if parts else ""
    return ""


def _has_mixed_scripts(host: str) -> bool:
    """Detect mixed Unicode scripts in hostname (excluding ASCII)."""
    # Remove ASCII parts
    non_ascii = [c for c in host if ord(c) > 127]
    if not non_ascii:
        return False

    # Check script diversity
    scripts = set()
    for char in non_ascii:
        # Basic script detection by Unicode block
        cp = ord(char)
        if 0x0400 <= cp <= 0x04FF:  # Cyrillic
            scripts.add("cyrillic")
        elif 0x0370 <= cp <= 0x03FF:  # Greek
            scripts.add("greek")
        elif 0x0500 <= cp <= 0x052F:  # Cyrillic Supplement
            scripts.add("cyrillic")
        elif 0x1E00 <= cp <= 0x1EFF:  # Latin Extended Additional
            scripts.add("latin_ext")
        elif 0x2000 <= cp <= 0x206F:  # General Punctuation
            scripts.add("punctuation")
        elif 0xFF00 <= cp <= 0xFFEF:  # Halfwidth and Fullwidth Forms
            scripts.add("fullwidth")
        else:
            scripts.add("other")

    return len(scripts) > 1


def _is_punycode(host: str) -> bool:
    """Check if host contains punycode (xn--)."""
    return "xn--" in host.lower()


def _check_typosquat(sld: str, brand_names: list[str]) -> tuple[bool, str | None]:
    """
    Check if SLD is a typosquat of any brand name.

    Returns:
        (is_typosquat, matched_brand)
    """
    sld_lower = sld.lower()
    sld_deleted = _deleet(sld_lower)

    for brand in brand_names:
        brand_lower = brand.lower()
        brand_deleted = _deleet(brand_lower)

        # Exact match after de-leeting
        if sld_deleted == brand_deleted and sld_lower != brand_lower:
            return True, brand

        # Levenshtein distance == 1
        if Levenshtein.distance(sld_lower, brand_lower) == 1:
            return True, brand

        # Levenshtein on de-leeted
        if Levenshtein.distance(sld_deleted, brand_deleted) == 1 and sld_lower != brand_lower:
            return True, brand

    return False, None


async def run(target: NormalisedUrl, settings: Any = None) -> tuple[list[Finding], CheckStatus]:
    """
    Run lexical analysis on a normalised URL.

    Args:
        target: NormalisedUrl to analyze
        settings: Optional settings (unused but kept for interface consistency)

    Returns:
        Tuple of (findings, check_status)
    """
    findings: list[Finding] = []
    _load_brand_data()

    host = target.host
    registrable_domain = target.registrable_domain
    suffix = target.suffix
    sld = _extract_sld(host, registrable_domain)

    # Get all brand names for typo checking
    brand_names = [b["name"] for b in _BRAND_DATA.get("brands", [])]

    # Check if target domain is protected (official brand, gov, edu, etc.)
    is_protected = _is_protected_domain(registrable_domain, suffix)

    # 1. Raw IP host
    if target.is_ip:
        findings.append(
            Finding(
                id="LEX_IP_HOST",
                check="lexical",
                title="Raw IP address used as host",
                severity=Severity.HIGH,
                evidence=f"Host is an IP address: {host}",
                source="lexical_analysis",
                confidence=1.0,
                weight=35,
                impact="Attackers often use raw IPs to avoid domain reputation checks",
                recommendation="Avoid interacting with services hosted on raw IP addresses",
            )
        )

    # 2. Embedded @ userinfo
    if target.has_userinfo:
        findings.append(
            Finding(
                id="LEX_USERINFO_AT",
                check="lexical",
                title="Embedded credentials in URL (userinfo)",
                severity=Severity.HIGH,
                evidence=f"URL contains userinfo: {target.original}",
                source="lexical_analysis",
                confidence=1.0,
                weight=40,
                impact="URLs with embedded credentials are commonly used in phishing to disguise the true destination",
                recommendation="Never trust URLs containing @ in the host portion",
            )
        )

    # 3. Punycode / IDN & mixed scripts
    if _is_punycode(host):
        findings.append(
            Finding(
                id="LEX_IDN_PUNYCODE",
                check="lexical",
                title="Punycode/IDN domain detected",
                severity=Severity.MEDIUM,
                evidence=f"Host contains punycode: {host}",
                source="lexical_analysis",
                confidence=0.8,
                weight=20,
                impact="Internationalized domain names can be used for homograph attacks",
                recommendation="Verify the domain carefully; punycode domains may visually mimic legitimate brands",
            )
        )

    if _has_mixed_scripts(target.unicode_host):
        findings.append(
            Finding(
                id="LEX_MIXED_SCRIPT",
                check="lexical",
                title="Mixed Unicode scripts in hostname",
                severity=Severity.HIGH,
                evidence=f"Host contains mixed scripts: {target.unicode_host}",
                source="lexical_analysis",
                confidence=0.9,
                weight=45,
                impact="Mixed-script domains are a hallmark of homograph phishing attacks",
                recommendation="Do not trust this domain; it likely mimics a legitimate brand using lookalike characters",
            )
        )

    # Skip brand spoofing checks for protected domains
    if not is_protected:
        # 4. Brand in subdomain
        host_parts = host.split(".")
        for i, part in enumerate(host_parts[:-1]):  # Exclude TLD and SLD
            part_lower = part.lower()
            for brand in _BRAND_DATA.get("brands", []):
                brand_name = brand["name"].lower()
                if brand_name in part_lower and part_lower != brand_name:
                    findings.append(
                        Finding(
                            id="LEX_BRAND_SUBDOMAIN",
                            check="lexical",
                            title=f"Brand name '{brand['display_name']}' found in subdomain",
                            severity=Severity.HIGH,
                            evidence=f"Subdomain contains brand: {part} (full host: {host})",
                            source="lexical_analysis",
                            confidence=0.85,
                            weight=45,
                            impact="Attackers place brand names in subdomains to trick users (e.g., paypal.evil.com)",
                            recommendation="Verify the registrable domain matches the official brand domain",
                        )
                    )

        # 5. Brand combo-squatting in SLD
        if sld:
            sld_lower = sld.lower()
            for brand in _BRAND_DATA.get("brands", []):
                brand_name = brand["name"].lower()
                # Check if brand name appears in SLD with extra words
                if brand_name in sld_lower and sld_lower != brand_name:
                    # Ensure it's not just the brand as exact SLD (which could be legit sub-brand)
                    extra = sld_lower.replace(brand_name, "")
                    if extra and len(extra) > 1:
                        findings.append(
                            Finding(
                                id="LEX_BRAND_COMBO",
                                check="lexical",
                                title=f"Combo-squatting: '{brand['display_name']}' with extra terms in domain",
                                severity=Severity.HIGH,
                                evidence=f"SLD '{sld}' contains brand '{brand_name}' plus extra: {extra}",
                                source="lexical_analysis",
                                confidence=0.8,
                                weight=40,
                                impact="Combo-squatting adds words like 'login', 'security', 'update' to brand names",
                                recommendation="Check if the registrable domain matches the official brand domain",
                            )
                        )

        # 6. Typosquatting
        is_typosquat, matched_brand = _check_typosquat(sld, brand_names)
        if is_typosquat and matched_brand:
            brand_info = next(b for b in _BRAND_DATA.get("brands", []) if b["name"] == matched_brand)
            findings.append(
                Finding(
                    id="LEX_TYPOSQUAT",
                    check="lexical",
                    title=f"Typosquatting detected: mimics '{brand_info['display_name']}'",
                    severity=Severity.HIGH,
                    evidence=f"SLD '{sld}' is a typo variant of '{matched_brand}'",
                    source="lexical_analysis",
                    confidence=0.85,
                    weight=40,
                    impact="Typosquatting exploits user typos to direct traffic to malicious sites",
                    recommendation=f"Verify you intended to visit the official {brand_info['display_name']} domain",
                )
            )

    # 7. Deep subdomains (>= 3 levels before registrable domain)
    subdomain_count = len(host.split(".")) - len(registrable_domain.split(".")) - 1
    if subdomain_count >= 3 and not is_protected:
        findings.append(
            Finding(
                id="LEX_DEEP_SUBDOMAIN",
                check="lexical",
                title=f"Deep subdomain nesting ({subdomain_count} levels)",
                severity=Severity.MEDIUM,
                evidence=f"Host has {subdomain_count} subdomain levels: {host}",
                source="lexical_analysis",
                confidence=0.6,
                weight=15,
                impact="Deep subdomains can hide the true registrable domain from casual inspection",
                recommendation="Verify the registrable domain (last 2-3 parts) is legitimate",
            )
        )

    # 8. Long host (> 75 chars)
    if len(host) > 75:
        findings.append(
            Finding(
                id="LEX_LONG_HOST",
                check="lexical",
                title="Excessively long hostname",
                severity=Severity.LOW,
                evidence=f"Host length: {len(host)} chars ({host})",
                source="lexical_analysis",
                confidence=0.5,
                weight=10,
                impact="Very long hostnames can obscure the true domain and are uncommon for legitimate sites",
                recommendation="Inspect the full hostname carefully",
            )
        )

    # 9. Suspicious TLD
    if suffix.lower() in SUSPICIOUS_TLDS and not is_protected:
        findings.append(
            Finding(
                id="LEX_SUSPICIOUS_TLD",
                check="lexical",
                title=f"Suspicious TLD: .{suffix}",
                severity=Severity.LOW,
                evidence=f"Domain uses TLD '.{suffix}' commonly associated with abuse",
                source="lexical_analysis",
                confidence=0.5,
                weight=15,
                impact="Certain TLDs have high abuse rates and low registration barriers",
                recommendation="Exercise extra caution with domains on this TLD",
            )
        )

    # 10. Lure keywords in path/query (only if not protected)
    if not is_protected:
        path_query = (target.path + "?" + target.query).lower()
        for keyword in LURE_KEYWORDS:
            if keyword in path_query:
                findings.append(
                    Finding(
                        id="LEX_LURE_KEYWORDS",
                        check="lexical",
                        title=f"Phishing lure keyword in path/query: '{keyword}'",
                        severity=Severity.MEDIUM,
                        evidence=f"Path/query contains lure term: {target.path}?{target.query}",
                        source="lexical_analysis",
                        confidence=0.6,
                        weight=20,
                        impact="Attackers use urgency and action keywords to manipulate users",
                        recommendation="Be wary of URLs demanding immediate action or verification",
                    )
                )
                break  # Only report once

    return findings, CheckStatus(check="lexical", ran=True, reason=None)