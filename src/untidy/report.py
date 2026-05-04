from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

from .models import Finding

COLUMNS = [
    "file_path",
    "file_type",
    "location",
    "entity_type",
    "detection_rule",
    "confidence",
    "match_snippet",
    "column_header",
]


def _mask(s: str) -> str:
    s = s.strip()
    if len(s) <= 4:
        return "*" * len(s)
    return "*" * (len(s) - 4) + s[-4:]


def write_csv(
    findings: Iterable[Finding], output_path: Path, mask: bool = True
) -> int:
    """Write findings to CSV. When mask is True, match_snippet is masked at
    write time — pass scan() unmasked findings and let the report decide, so
    we can emit both masked and unmasked reports from a single scan."""
    count = 0
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        for f in findings:
            snippet = _mask(f.match_snippet) if mask else f.match_snippet
            writer.writerow(
                {
                    "file_path": f.file_path,
                    "file_type": f.file_type,
                    "location": f.location,
                    "entity_type": f.entity_type,
                    "detection_rule": f.detection_rule,
                    "confidence": f.confidence,
                    "match_snippet": snippet,
                    "column_header": f.column_header or "",
                }
            )
            count += 1
    return count
