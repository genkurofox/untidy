"""Column-header heuristics for tabular data.

Maps normalized header names (lowercased, non-alnum stripped) to the entity
type they imply. When a header matches, every non-empty cell in that column
is flagged — this is how we catch free-text names/addresses without NER.
"""
from __future__ import annotations

import re
from typing import Optional

HEADER_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(^|_)ssn($|_)"), "SSN"),
    (re.compile(r"social.*sec"), "SSN"),
    (re.compile(r"(^|_)mrn($|_)"), "MRN"),
    (re.compile(r"medical.*record"), "MRN"),
    (re.compile(r"patient.*id"), "PATIENT_ID"),
    (re.compile(r"(^|_)npi($|_)"), "NPI"),
    (re.compile(r"(^|_)dob($|_)"), "DOB"),
    (re.compile(r"date.*of.*birth|birth.*date|birthdate"), "DOB"),
    (re.compile(r"first.*name|fname|given.*name"), "NAME"),
    (re.compile(r"last.*name|lname|surname|family.*name"), "NAME"),
    (re.compile(r"patient.*name|full.*name|(^|_)name($|_)"), "NAME"),
    (re.compile(r"middle.*name|middle.*initial"), "NAME"),
    (re.compile(r"street|address|addr"), "ADDRESS"),
    (re.compile(r"(^|_)city($|_)"), "ADDRESS"),
    (re.compile(r"(^|_)state($|_)"), "ADDRESS"),
    (re.compile(r"(^|_)zip($|_)|postal.*code"), "ZIP_CODE"),
    (re.compile(r"(^|_)phone($|_)|phone.*number|mobile|cell"), "PHONE_US"),
    (re.compile(r"(^|_)email($|_)|e.?mail"), "EMAIL"),
    (re.compile(r"diagnosis|icd.?10|icd.?9"), "DIAGNOSIS"),
    (re.compile(r"insurance|policy.*num"), "INSURANCE"),
    (re.compile(r"credit.*card|(^|_)cc.*num|card.*number"), "CREDIT_CARD"),
    (re.compile(r"(^|_)iban($|_)|bank.*account|account.*number"), "IBAN"),
    (re.compile(r"(^|_)swift($|_)|bic.*code"), "SWIFT"),
    (re.compile(r"passport"), "PASSPORT"),
    (re.compile(r"driver.?s?.?licen[sc]e|(^|_)dl.?(num|number|no)?($|_)"), "DRIVERS_LICENSE"),
    (re.compile(r"(^|_)api.?key($|_)|secret.?key|access.?token|auth.?token"), "SECRET"),
    (re.compile(r"(^|_)password($|_)|passwd|pwd"), "PASSWORD"),
    (re.compile(r"routing.?(num|number|no)"), "ROUTING_NUMBER"),
]


def _normalize(header: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", header.strip().lower()).strip("_")


def entity_for_header(header: Optional[str]) -> Optional[str]:
    if not header:
        return None
    norm = _normalize(header)
    for pat, entity in HEADER_RULES:
        if pat.search(norm):
            return entity
    return None


# Columns whose names strongly indicate the value is an identifier that happens
# to have digits, not a credit card. Prevents Luhn-valid tx_ids/order_ids/etc.
# from being flagged as CREDIT_CARD.
_NON_PAN_HEADERS = re.compile(
    r"(?:^|_)(?:"
    r"tx|txn|transaction|order|invoice|receipt|shipment|tracking|"
    r"barcode|upc|ean|isbn|sku|batch|lot|session|request|trace|correlation"
    r")(?:_id|_num(?:ber)?|_no)?(?:$|_)"
    r"|tracking_number"
)


def suppresses_credit_card(header: Optional[str]) -> bool:
    """True when a header name indicates its cells hold non-PAN identifiers."""
    if not header:
        return False
    norm = _normalize(header)
    if _NON_PAN_HEADERS.search(norm):
        return True
    return False
