"""T-SQL reader.

Sensitive values in SQL files typically appear as string literals (e.g.
``WHERE ssn = '123-45-6789'`` or ``INSERT INTO ... VALUES ('John', ...)``)
or in comments (``-- patient John Doe, MRN 12345678``). We flag both.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

import sqlparse
from sqlparse import tokens as T

from ..models import Chunk


def _line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def read(path: Path) -> Iterator[Chunk]:
    source = path.read_text(encoding="utf-8", errors="replace")
    parsed = sqlparse.parse(source)

    # sqlparse does not expose absolute offsets on tokens; rebuild them by
    # walking the flattened token stream in order.
    offset = 0
    for statement in parsed:
        for token in statement.flatten():
            value = token.value
            if token.ttype in (
                T.Literal.String.Single,
                T.Literal.String.Symbol,
            ):
                inner = value.strip("'\"")
                if inner:
                    yield Chunk(
                        file_path=str(path),
                        file_type="sql",
                        location=f"line={_line_of(source, offset)}",
                        text=inner,
                    )
            elif token.ttype in (T.Comment, T.Comment.Single, T.Comment.Multiline):
                if value.strip():
                    yield Chunk(
                        file_path=str(path),
                        file_type="sql",
                        location=f"line={_line_of(source, offset)} (comment)",
                        text=value,
                    )
            offset += len(value)
