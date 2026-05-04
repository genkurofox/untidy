from __future__ import annotations

import fnmatch
import sys
from pathlib import Path
from typing import Callable, Iterable, Iterator

from .detectors.base import detect
from .models import Chunk, Finding
from .readers import (
    csv_reader,
    docx_reader,
    excel_reader,
    json_reader,
    pdf_reader,
    sql_reader,
    text_reader,
)

ReaderFn = Callable[[Path], Iterator[Chunk]]

READERS: dict[str, ReaderFn] = {
    ".csv": csv_reader.read,
    ".xlsx": excel_reader.read,
    ".sql": sql_reader.read,
    ".txt": text_reader.read,
    ".log": text_reader.read,
    ".md": text_reader.read,
    ".pdf": pdf_reader.read,
    ".docx": docx_reader.read,
    ".json": json_reader.read,
    ".ndjson": json_reader.read,
    ".yaml": json_reader.read,
    ".yml": json_reader.read,
}

DEFAULT_EXTS = tuple(READERS.keys())


def _iter_files(
    roots: Iterable[Path],
    include_ext: Iterable[str],
    excludes: Iterable[str],
    max_size_bytes: int,
    verbose: bool,
) -> Iterator[Path]:
    exts = {e.lower() for e in include_ext}
    excludes = list(excludes)
    for root in roots:
        if root.is_file():
            if root.suffix.lower() in exts:
                yield root
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in exts:
                continue
            rel = str(path)
            if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                continue
            try:
                if path.stat().st_size > max_size_bytes:
                    if verbose:
                        print(f"skip (too large): {path}", file=sys.stderr)
                    continue
            except OSError:
                continue
            yield path


def scan(
    roots: Iterable[Path],
    include_ext: Iterable[str] = DEFAULT_EXTS,
    excludes: Iterable[str] = (),
    max_size_mb: int = 200,
    mask: bool = True,
    verbose: bool = False,
    errors_out: list[str] | None = None,
) -> Iterator[Finding]:
    """Yield findings across roots. If errors_out is provided, per-file read
    errors append to it (the message includes the path) — callers can use this
    to distinguish "no findings" from "couldn't read some files"."""
    max_bytes = max_size_mb * 1024 * 1024
    for path in _iter_files(roots, include_ext, excludes, max_bytes, verbose):
        reader = READERS.get(path.suffix.lower())
        if reader is None:
            continue
        if verbose:
            print(f"scanning: {path}", file=sys.stderr)
        try:
            for chunk in reader(path):
                yield from detect(chunk, mask=mask)
        except Exception as e:  # keep scanning other files on per-file errors
            # Always include the exception class — some libraries raise
            # exceptions with empty messages, which used to produce a useless
            # "error scanning <path>:" line.
            msg = f"error scanning {path}: {type(e).__name__}: {e}"
            print(msg, file=sys.stderr)
            if errors_out is not None:
                errors_out.append(msg)
