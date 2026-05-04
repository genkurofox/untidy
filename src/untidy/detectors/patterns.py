"""Compiled regex patterns for value-level sensitive-data detection.

Each entry: entity_type -> (pattern, validator_or_None, confidence).
Validators receive the match string and return bool.
"""
from __future__ import annotations

import re
from typing import Callable, Optional

from . import checksums

_Validator = Optional[Callable[[str], bool]]

SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b")
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?1[-.\s]?)?\(?([2-9]\d{2})\)?[-.\s]?([2-9]\d{2})[-.\s]?(\d{4})(?!\d)"
)
CC_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
DATE_RE = re.compile(
    r"\b("
    r"(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"|"
    r"(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}"
    r")\b"
)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
# IPv6: full and compressed forms. Avoid trailing/leading-colon edge cases.
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|"
    r"[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})"
    r"|"
    r":(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)"
    r")"
    r"(?![0-9A-Fa-f:])"
)
ZIP_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")
MRN_RE = re.compile(r"\b\d{6,10}\b")
ROUTING_RE = re.compile(r"\b\d{9}\b")

# E.164-style international phone (not US). Require + prefix and a non-1 country
# code so we don't double-flag US numbers already caught by PHONE_RE. Allow
# internal whitespace between groups so "+44 20 7946 0958" parses.
PHONE_INTL_RE = re.compile(
    r"(?<![\d+])\+(?!1[\s.-]?\d)(?:\d[\s.-]?){7,15}\d(?!\d)"
)

# IBAN: country (2 alpha) + 2 check digits + 11-30 alphanumerics. 15-34 total.
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

# US passport: 1 letter or digit + 8 digits (modern format), or 9 digits.
# Keyword-gated below to avoid colliding with other 9-digit identifiers.
PASSPORT_INLINE_RE = re.compile(
    r"(?i)\bpassport(?:\s*(?:no|number|#))?[^\w]{0,10}([A-Z0-9]\d{8}|\d{9})\b"
)

# US driver's license is wildly state-dependent (1-9 chars, alpha+digit).
# Only fire on inline keyword to keep noise down.
DL_INLINE_RE = re.compile(
    r"(?i)\b(?:driver'?s?\s*licen[sc]e|dl\s*(?:no|number|#)?)[^\w]{0,10}([A-Z0-9]{4,12})\b"
)

# ICD-10: 1 letter + 2 digits, optional . then up to 4 alphanumerics.
ICD10_INLINE_RE = re.compile(
    r"(?i)\b(?:icd-?10|diagnosis|dx)[^\w]{0,10}([A-Z]\d{2}(?:\.[A-Z0-9]{1,4})?)\b"
)

# --- Secrets / API keys -----------------------------------------------------

# AWS Access Key ID: AKIA / ASIA / AGPA / AIDA / etc. + 16 uppercase alnum.
AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b")
# AWS Secret Access Key (inline keyword; standalone is too generic).
AWS_SECRET_INLINE_RE = re.compile(
    r"(?i)aws[_\-\s]?secret(?:[_\-\s]?access)?(?:[_\-\s]?key)?"
    r"[\s:=\"']{0,10}([A-Za-z0-9/+=]{40})\b"
)
# GitHub PATs / OAuth / app / refresh tokens: ghp_, gho_, ghu_, ghs_, ghr_.
GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")
# Slack tokens: xox[abprs]-...
SLACK_TOKEN_RE = re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")
# Stripe live/test keys.
STRIPE_KEY_RE = re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b")
# Google API key.
GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
# JWT: three base64url segments separated by dots.
JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"
)
# PEM private keys (RSA, EC, OPENSSH, plain).
PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
)


def _luhn_validator(s: str) -> bool:
    return checksums.luhn_valid(s)


def _ssn_validator(s: str) -> bool:
    return checksums.ssn_valid(s)


def _routing_validator(s: str) -> bool:
    return checksums.routing_valid(s)


def _iban_validator(s: str) -> bool:
    return checksums.iban_valid(s)


# Ordered: more specific / higher-confidence detectors first so we can suppress
# weaker ones that overlap. The scanner dedupes by (location, span) to respect this.
VALUE_DETECTORS: list[tuple[str, re.Pattern[str], _Validator, str, str]] = [
    # Secrets first — distinctive prefixes, near-zero false positives.
    ("AWS_ACCESS_KEY_ID", AWS_ACCESS_KEY_RE, None, "regex", "high"),
    ("GITHUB_TOKEN", GITHUB_TOKEN_RE, None, "regex", "high"),
    ("SLACK_TOKEN", SLACK_TOKEN_RE, None, "regex", "high"),
    ("STRIPE_KEY", STRIPE_KEY_RE, None, "regex", "high"),
    ("GOOGLE_API_KEY", GOOGLE_API_KEY_RE, None, "regex", "high"),
    ("JWT", JWT_RE, None, "regex", "high"),
    ("PRIVATE_KEY", PEM_PRIVATE_KEY_RE, None, "regex", "high"),
    # PII identifiers.
    ("SSN", SSN_RE, _ssn_validator, "regex+validity", "high"),
    ("CREDIT_CARD", CC_RE, _luhn_validator, "regex+luhn", "high"),
    ("EMAIL", EMAIL_RE, None, "regex", "high"),
    ("PHONE_US", PHONE_RE, None, "regex", "high"),
    ("PHONE_INTL", PHONE_INTL_RE, None, "regex", "medium"),
    ("IBAN", IBAN_RE, _iban_validator, "regex+checksum", "high"),
    ("DATE", DATE_RE, None, "regex", "medium"),
    ("IP_ADDRESS", IPV4_RE, None, "regex", "medium"),
    ("IPV6_ADDRESS", IPV6_RE, None, "regex", "medium"),
    ("ROUTING_NUMBER", ROUTING_RE, _routing_validator, "regex+checksum", "medium"),
    # ZIP_CODE intentionally omitted from value-level detectors: any 5-digit run
    # produces too many false positives (order IDs, SKUs, counts). A zip column
    # still gets flagged via the header heuristic as ZIP_CODE_FROM_HEADER.
]

# Inline (keyword-gated) detectors. Group 1 is the captured value.
# Order matters: all run regardless of header context, but each is keyword-gated
# so collisions with VALUE_DETECTORS are rare.
INLINE_DETECTORS: list[tuple[str, re.Pattern[str], _Validator, str, str]] = [
    ("PASSPORT", PASSPORT_INLINE_RE, None, "regex+inline_keyword", "high"),
    ("DRIVERS_LICENSE", DL_INLINE_RE, None, "regex+inline_keyword", "medium"),
    ("ICD10", ICD10_INLINE_RE, None, "regex+inline_keyword", "medium"),
    ("AWS_SECRET_ACCESS_KEY", AWS_SECRET_INLINE_RE, None, "regex+inline_keyword", "high"),
]

# Inline name/address/DOB free-text keyword patterns. Same trick as MRN_INLINE_RE:
# require a label keyword within ~20 chars of a value to avoid generic matching.
NAME_INLINE_RE = re.compile(
    r"(?im)\b(?:patient(?:\s*name)?|full[\s_-]?name|first[\s_-]?name|last[\s_-]?name|name)"
    r"\s*[:=]\s*([A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){1,3})"
)
ADDRESS_INLINE_RE = re.compile(
    r"(?im)\b(?:address|addr|street)\s*[:=]\s*"
    r"(\d+\s+[A-Za-z][A-Za-z0-9'.\-\s]{2,80}"
    r"(?:\s(?:st|street|ave|avenue|blvd|boulevard|rd|road|dr|drive|ln|lane|way|ct|court|pl|place))\b\.?)"
)
DOB_INLINE_RE = re.compile(
    r"(?i)\b(?:dob|date[\s_-]?of[\s_-]?birth|birth[\s_-]?date|birthday)"
    r"\s*[:=]?\s*"
    r"((?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01])"
    r"|(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)?\d{2})"
)

NAME_ADDRESS_DOB_INLINE: list[tuple[str, re.Pattern[str], str, str]] = [
    ("NAME", NAME_INLINE_RE, "regex+inline_keyword", "medium"),
    ("ADDRESS", ADDRESS_INLINE_RE, "regex+inline_keyword", "medium"),
    ("DOB", DOB_INLINE_RE, "regex+inline_keyword", "high"),
]

# MRN is ambiguous (any 6-10 digit run). Only run it when a header or SQL column
# name hints at medical-record context.
MRN_PATTERN = MRN_RE

# Inline MRN: keyword within ~20 chars of a 6-10 digit run. Catches ad-hoc
# references in SQL comments like `-- patient John Doe, MRN 12345678` and in free text.
MRN_INLINE_RE = re.compile(
    r"(?i)\b(?:mrn|medical[\s_-]?record(?:\s*(?:no|number|#))?|patient[\s_-]?id)"
    r"[^\w]{0,20}(\d{6,10})\b"
)
