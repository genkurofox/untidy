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
ZIP_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")
MRN_RE = re.compile(r"\b\d{6,10}\b")
ROUTING_RE = re.compile(r"\b\d{9}\b")


def _luhn_validator(s: str) -> bool:
    return checksums.luhn_valid(s)


def _ssn_validator(s: str) -> bool:
    return checksums.ssn_valid(s)


def _routing_validator(s: str) -> bool:
    return checksums.routing_valid(s)


# Ordered: more specific / higher-confidence detectors first so we can suppress
# weaker ones that overlap. The scanner dedupes by (location, span) to respect this.
VALUE_DETECTORS: list[tuple[str, re.Pattern[str], _Validator, str, str]] = [
    ("SSN", SSN_RE, _ssn_validator, "regex+validity", "high"),
    ("CREDIT_CARD", CC_RE, _luhn_validator, "regex+luhn", "high"),
    ("EMAIL", EMAIL_RE, None, "regex", "high"),
    ("PHONE_US", PHONE_RE, None, "regex", "high"),
    ("DATE", DATE_RE, None, "regex", "medium"),
    ("IP_ADDRESS", IPV4_RE, None, "regex", "medium"),
    ("ROUTING_NUMBER", ROUTING_RE, _routing_validator, "regex+checksum", "medium"),
    # ZIP_CODE intentionally omitted from value-level detectors: any 5-digit run
    # produces too many false positives (order IDs, SKUs, counts). A zip column
    # still gets flagged via the header heuristic as ZIP_CODE_FROM_HEADER.
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
