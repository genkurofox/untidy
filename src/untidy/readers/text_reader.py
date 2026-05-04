from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..models import Chunk


def read(path: Path) -> Iterator[Chunk]:
    file_type = path.suffix.lstrip(".").lower() or "text"
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_num, line in enumerate(fh, start=1):
            stripped = line.rstrip("\n")
            if not stripped:
                continue
            yield Chunk(
                file_path=str(path),
                file_type=file_type,
                location=f"line={line_num}",
                text=stripped,
            )
