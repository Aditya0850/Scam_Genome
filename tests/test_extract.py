"""Tests for trustlens.message.extract."""

import pytest

from trustlens.message.extract import (
    extract_all,
    extract_phones,
    extract_upi_ids,
    extract_urls,
)


def test_email_is_not_returned_as_a_upi_id() -> None:
    result = extract_all("contact user@example.com")
    assert [e.refanged for e in result.emails] == ["user@example.com"]
    assert result.upi_ids == []
    assert extract_upi_ids("user@example.com") == []


def test_upi_id_is_detected() -> None:
    result = extract_all("pay to name@oksbi")
    assert [u.original for u in result.upi_ids] == ["name@oksbi"]
    assert result.emails == []


def test_obfuscated_url_is_refanged() -> None:
    urls = extract_urls("visit hxxp://evil[.]com now")
    assert [u.original for u in urls] == ["hxxp://evil[.]com"]
    assert [u.refanged for u in urls] == ["http://evil.com"]


@pytest.mark.parametrize(
    "text",
    [
        "+91 98765 43210",
        "+91-98765-43210",
        "98765 43210",
        "call 9876543210 now",
    ],
)
def test_indian_mobile_formats_are_found_once(text: str) -> None:
    phones = extract_phones(text)
    assert len(phones) == 1
    assert phones[0].normalized == "+919876543210"
    assert phones[0].country_code == "IN"


def test_digit_run_does_not_yield_a_phone_number() -> None:
    assert extract_phones("reference 129876543210 here") == []


def test_phone_details_are_kept() -> None:
    result = extract_all("call +91-98765-43210")
    assert len(result.phones) == 1
    assert result.phones[0].original == "+91-98765-43210"
    assert result.phones[0].normalized == "+919876543210"
