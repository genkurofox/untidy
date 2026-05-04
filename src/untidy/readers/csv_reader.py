from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator

from ..models import Chunk


def read(path: Path) -> Iterator[Chunk]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh)
        try:
            headers = next(reader)
        except StopIteration:
            return
        for row_num, row in enumerate(reader, start=2):
            for col_idx, cell in enumerate(row):
                if cell is None or cell == "":
                    continue
                header = headers[col_idx] if col_idx < len(headers) else None
                yield Chunk(
                    file_path=str(path),
                    file_type="csv",
                    location=f"row={row_num} col={header or col_idx + 1}",
                    text=str(cell),
                    column_header=header,
                )
