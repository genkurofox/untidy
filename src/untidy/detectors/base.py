"""Run detectors against a Chunk and produce Findings."""
from __future__ import annotations

from typing import Iterable

from ..models import Chunk, Finding
from . import headers, patterns


def _mask(s: str) -> str:
    s = s.strip()
    if len(s) <= 4:
        return "*" * len(s)
    return "*" * (len(s) - 4) + s[-4:]


def _snippet(match: str, mask: bool) -> str:
    match = match.strip()
    return _mask(match) if mask else match


def detect(chunk: Chunk, mask: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    text = chunk.text or ""
    seen_spans: set[tuple[int, int]] = set()

    header_entity = headers.entity_for_header(chunk.column_header)

    # Header-implied finding for tabular data: the value itself is the evidence.
    if header_entity and text.strip():
        findings.append(
            Finding(
                file_path=chunk.file_path,
                file_type=chunk.file_type,
                location=chunk.location,
                entity_type=f"{header_entity}_FROM_HEADER",
                detection_rule="header_match",
                confidence="high",
                match_snippet=_mask(text) if mask else text,
                column_header=chunk.column_header,
            )
        )

    # Run inline (keyword-gated) detectors FIRST so they win span-dedup against
    # the more generic value detectors below — DOB > DATE, PASSPORT > digit run.
    for entity, regex, validator, rule, confidence in patterns.INLINE_DETECTORS:
        for m in regex.finditer(text):
            value = m.group(1)
            value_span = m.span(1)
            if value_span in seen_spans:
                continue
            if validator and not validator(value):
                continue
            seen_spans.add(value_span)
            findings.append(
                Finding(
                    file_path=chunk.file_path,
                    file_type=chunk.file_type,
                    location=chunk.location,
                    entity_type=entity,
                    detection_rule=rule,
                    confidence=confidence,
                    match_snippet=_snippet(value, mask),
                    column_header=chunk.column_header,
                )
            )

    # Inline NAME / ADDRESS / DOB free-text patterns. Same trick as MRN_INLINE.
    for entity, regex, rule, confidence in patterns.NAME_ADDRESS_DOB_INLINE:
        for m in regex.finditer(text):
            value = m.group(1)
            value_span = m.span(1)
            if value_span in seen_spans:
                continue
            seen_spans.add(value_span)
            findings.append(
                Finding(
                    file_path=chunk.file_path,
                    file_type=chunk.file_type,
                    location=chunk.location,
                    entity_type=entity,
                    detection_rule=rule,
                    confidence=confidence,
                    match_snippet=_snippet(value, mask),
                    column_header=chunk.column_header,
                )
            )

    # MRN via inline keyword context: catches ad-hoc references in SQL comments
    # or free text like "-- patient John Doe, MRN 12345678".
    for m in patterns.MRN_INLINE_RE.finditer(text):
        digits = m.group(1)
        digit_span = m.span(1)
        if digit_span in seen_spans:
            continue
        seen_spans.add(digit_span)
        findings.append(
            Finding(
                file_path=chunk.file_path,
                file_type=chunk.file_type,
                location=chunk.location,
                entity_type="MRN",
                detection_rule="regex+inline_keyword",
                confidence="high",
                match_snippet=_snippet(digits, mask),
                column_header=chunk.column_header,
            )
        )

    # MRN via tabular header context: every digit run in the cell.
    if header_entity in {"MRN", "PATIENT_ID"}:
        for m in patterns.MRN_PATTERN.finditer(text):
            span = m.span()
            if span in seen_spans:
                continue
            seen_spans.add(span)
            findings.append(
                Finding(
                    file_path=chunk.file_path,
                    file_type=chunk.file_type,
                    location=chunk.location,
                    entity_type="MRN",
                    detection_rule="regex+header_context",
                    confidence="high",
                    match_snippet=_snippet(m.group(0), mask),
                    column_header=chunk.column_header,
                )
            )

    cc_suppressed = headers.suppresses_credit_card(chunk.column_header)

    for entity, regex, validator, rule, confidence in patterns.VALUE_DETECTORS:
        if entity == "CREDIT_CARD" and cc_suppressed:
            continue
        for m in regex.finditer(text):
            span = m.span()
            if span in seen_spans:
                continue
            matched = m.group(0)
            if validator and not validator(matched):
                continue
            seen_spans.add(span)
            findings.append(
                Finding(
                    file_path=chunk.file_path,
                    file_type=chunk.file_type,
                    location=chunk.location,
                    entity_type=entity,
                    detection_rule=rule,
                    confidence=confidence,
                    match_snippet=_snippet(matched, mask),
                    column_header=chunk.column_header,
                )
            )

    return findings


def detect_all(chunks: Iterable[Chunk], mask: bool = True) -> list[Finding]:
    out: list[Finding] = []
    for c in chunks:
        out.extend(detect(c, mask=mask))
    return out
