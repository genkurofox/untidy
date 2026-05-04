from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Chunk:
    """A piece of text pulled out of a source file, with enough context to locate it."""

    file_path: str
    file_type: str
    location: str
    text: str
    column_header: Optional[str] = None


@dataclass(frozen=True)
class Finding:
    file_path: str
    file_type: str
    location: str
    entity_type: str
    detection_rule: str
    confidence: str
    match_snippet: str
    column_header: Optional[str] = None
