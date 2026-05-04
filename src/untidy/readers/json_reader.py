"""JSON / NDJSON / YAML reader.

Walks nested structures and yields a Chunk per primitive value. The dict key
is passed as ``column_header`` so the header heuristic catches things like
``{"first_name": "Jane"}`` even though there are no tabular columns.

YAML support is best-effort — if PyYAML isn't installed, we fall back to JSON
parsing and skip YAML files instead of erroring.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from ..models import Chunk


def _walk(value: Any, path: str, header: str | None) -> Iterator[tuple[str, str, str | None]]:
    """Yield (location_path, text, column_header) for every primitive."""
    if value is None:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            key = str(k)
            yield from _walk(v, f"{path}.{key}" if path else key, header=key)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _walk(item, f"{path}[{i}]", header=header)
    else:
        s = str(value)
        if s == "":
            return
        yield (path or "$", s, header)


def _file_type(path: Path) -> str:
    return path.suffix.lstrip(".").lower() or "json"


def read(path: Path) -> Iterator[Chunk]:
    suffix = path.suffix.lower()
    file_type = _file_type(path)

    if suffix == ".ndjson":
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_num, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for loc, text, header in _walk(obj, "", None):
                    yield Chunk(
                        file_path=str(path),
                        file_type=file_type,
                        location=f"line={line_num} {loc}",
                        text=text,
                        column_header=header,
                    )
        return

    raw = path.read_text(encoding="utf-8", errors="replace")
    if suffix in {".yaml", ".yml"}:
        if not _HAS_YAML:
            return
        loaded = yaml.safe_load(raw)
    else:
        loaded = json.loads(raw)

    for loc, text, header in _walk(loaded, "", None):
        yield Chunk(
            file_path=str(path),
            file_type=file_type,
            location=loc,
            text=text,
            column_header=header,
        )
