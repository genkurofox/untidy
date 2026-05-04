"""T-SQL reader.

Sensitive values in SQL files typically appear as string literals (e.g.
``WHERE ssn = '123-45-6789'`` or ``INSERT INTO ... VALUES ('John', ...)``)
or in comments (``-- patient John Doe, MRN 12345678``). We flag both.

Implementation note: sqlparse imposes a per-document token limit and chokes on
multi-megabyte SQL dumps (`maximum number of tokens exceeded`). We use direct
regex extraction instead — it handles arbitrary file sizes and covers what we
actually care about (single-quoted string literals, line comments, block
comments). Identifier/double-quoted tokens are intentionally not extracted
since identifiers aren't sensitive data on their own.
"""
from __future__ import annotations

import bisect
import re
from pathlib import Path
from typing import Iterator

from ..models import Chunk

# Single-quoted SQL string literal with `''` as the SQL escape for an embedded
# quote. Group 1 is the inner content.
_SQL_STRING = re.compile(r"'((?:[^']|'')*)'")
_SQL_LINE_COMMENT = re.compile(r"--[^\n]*")
_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def _line_index(source: str) -> list[int]:
    """Sorted list of newline positions; bisect against this for O(log n)
    line lookups instead of O(n) per-match scans."""
    return [i for i, c in enumerate(source) if c == "\n"]


def read(path: Path) -> Iterator[Chunk]:
    source = path.read_text(encoding="utf-8", errors="replace")
    nl = _line_index(source)

    def line_of(offset: int) -> int:
        return bisect.bisect_left(nl, offset) + 1

    for m in _SQL_STRING.finditer(source):
        inner = m.group(1).replace("''", "'")
        if inner:
            yield Chunk(
                file_path=str(path),
                file_type="sql",
                location=f"line={line_of(m.start())}",
                text=inner,
            )

    for pat in (_SQL_LINE_COMMENT, _SQL_BLOCK_COMMENT):
        for m in pat.finditer(source):
            text = m.group(0)
            if text.strip():
                yield Chunk(
                    file_path=str(path),
                    file_type="sql",
                    location=f"line={line_of(m.start())} (comment)",
                    text=text,
                )
