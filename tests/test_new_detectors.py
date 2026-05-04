"""Tests for the gap-closing detectors: secrets, international IDs, inline
NAME/ADDRESS/DOB free-text patterns."""
from __future__ import annotations

from untidy.detectors import checksums, headers
from untidy.detectors.base import detect
from untidy.models import Chunk


def _detect(text: str, header: str | None = None, file_type: str = "text"):
    c = Chunk(file_path="f", file_type=file_type, location="l", text=text,
              column_header=header)
    return detect(c, mask=False)


# --- Secrets ---------------------------------------------------------------

def test_aws_access_key_id_detected():
    findings = _detect("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    assert any(f.entity_type == "AWS_ACCESS_KEY_ID" for f in findings)


def test_aws_secret_access_key_inline():
    findings = _detect("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert any(f.entity_type == "AWS_SECRET_ACCESS_KEY" for f in findings)


def test_github_token_detected():
    findings = _detect("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
    assert any(f.entity_type == "GITHUB_TOKEN" for f in findings)


def test_slack_token_detected():
    findings = _detect("xoxb-1234567890-abcdefghij")
    assert any(f.entity_type == "SLACK_TOKEN" for f in findings)


def test_stripe_key_detected():
    # Build the fixture at runtime so no literal Stripe-shaped string lands in
    # source — GitHub's secret scanner blocks pushes that contain one even when
    # the value is obviously synthetic.
    fake_key = "sk_" + "test_" + "abcdefghijklmnop12345678"
    findings = _detect(fake_key)
    assert any(f.entity_type == "STRIPE_KEY" for f in findings)


def test_google_api_key_detected():
    # Google API keys are 39 chars: AIza + 35 alphanumerics/_/-.
    findings = _detect("api_key=AIzaSyA-1234567890abcdefghijklmnopqrstu")
    assert any(f.entity_type == "GOOGLE_API_KEY" for f in findings)


def test_jwt_detected():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    findings = _detect(f"Authorization: Bearer {jwt}")
    assert any(f.entity_type == "JWT" for f in findings)


def test_pem_private_key_detected():
    findings = _detect("-----BEGIN RSA PRIVATE KEY-----\nMIIBOQ...")
    assert any(f.entity_type == "PRIVATE_KEY" for f in findings)


# --- International / identity ----------------------------------------------

def test_iban_valid_checksum():
    # Real IBAN test vector (German example from ISO 13616).
    assert checksums.iban_valid("DE89370400440532013000")


def test_iban_invalid_checksum():
    assert not checksums.iban_valid("DE00370400440532013000")


def test_iban_detected_in_text():
    findings = _detect("Wire to IBAN DE89370400440532013000")
    assert any(f.entity_type == "IBAN" for f in findings)


def test_iban_rejects_bad_checksum_in_text():
    findings = _detect("ref DE00370400440532013000")
    assert not any(f.entity_type == "IBAN" for f in findings)


def test_ipv6_detected():
    findings = _detect("client connected from 2001:db8::8a2e:370:7334")
    assert any(f.entity_type == "IPV6_ADDRESS" for f in findings)


def test_intl_phone_detected():
    findings = _detect("call +44 20 7946 0958 today")
    assert any(f.entity_type == "PHONE_INTL" for f in findings)


def test_us_phone_not_double_flagged_as_intl():
    findings = _detect("call +1 415 555 0199")
    types = [f.entity_type for f in findings]
    assert "PHONE_US" in types
    assert "PHONE_INTL" not in types


def test_passport_inline():
    findings = _detect("passport no. A12345678 issued 2020")
    assert any(f.entity_type == "PASSPORT" for f in findings)


def test_drivers_license_inline():
    findings = _detect("driver's license: D1234567")
    assert any(f.entity_type == "DRIVERS_LICENSE" for f in findings)


def test_icd10_inline():
    findings = _detect("Diagnosis: E11.9 type 2 diabetes")
    assert any(f.entity_type == "ICD10" for f in findings)


# --- Inline NAME / ADDRESS / DOB -------------------------------------------

def test_inline_name():
    findings = _detect("Patient name: Maria Garcia")
    assert any(f.entity_type == "NAME" for f in findings)


def test_inline_address():
    findings = _detect("address: 123 Market Street")
    assert any(f.entity_type == "ADDRESS" for f in findings)


def test_inline_dob_iso():
    findings = _detect("DOB: 1980-03-15")
    assert any(f.entity_type == "DOB" for f in findings)


def test_inline_dob_us_format():
    findings = _detect("date of birth 03/15/1980")
    assert any(f.entity_type == "DOB" for f in findings)


# --- Header rules -----------------------------------------------------------

def test_iban_header():
    assert headers.entity_for_header("iban") == "IBAN"
    assert headers.entity_for_header("bank_account_number") == "IBAN"


def test_passport_header():
    assert headers.entity_for_header("passport_number") == "PASSPORT"


def test_dl_header():
    assert headers.entity_for_header("drivers_license") == "DRIVERS_LICENSE"
    assert headers.entity_for_header("dl_number") == "DRIVERS_LICENSE"


def test_password_header_flags_value():
    findings = _detect("hunter2", header="password")
    types = {f.entity_type for f in findings}
    assert "PASSWORD_FROM_HEADER" in types
