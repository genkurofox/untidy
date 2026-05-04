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


def write_csv(findings: Iterable[Finding], output_path: Path) -> int:
    count = 0
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        for f in findings:
            writer.writerow(
                {
                    "file_path": f.file_path,
                    "file_type": f.file_type,
                    "location": f.location,
                    "entity_type": f.entity_type,
                    "detection_rule": f.detection_rule,
                    "confidence": f.confidence,
                    "match_snippet": f.match_snippet,
                    "column_header": f.column_header or "",
                }
            )
            count += 1
    return count
