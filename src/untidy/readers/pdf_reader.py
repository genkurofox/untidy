"""PDF reader. Yields one Chunk per page.

Uses pdfminer.six for text extraction. Encrypted or scanned (image-only) PDFs
will yield empty text — surface that as zero chunks rather than an error so the
scanner can keep going.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

from pdfminer.high_level import extract_pages
from pdfminer.layout import LTTextContainer

from ..models import Chunk

# pdfminer is chatty: "Could not get FontBBox", "metadata field indicating that
# it should not allow text extraction", etc. These are recoverable diagnostics,
# not failures we can act on. Mute them by default; users who want pdfminer's
# warnings can set the PDFMINER_LOG env var.
import os as _os
if not _os.environ.get("PDFMINER_LOG"):
    for _name in ("pdfminer", "pdfminer.pdffont", "pdfminer.pdfinterp",
                  "pdfminer.pdfpage", "pdfminer.pdfparser", "pdfminer.cmapdb",
                  "pdfminer.layout", "pdfminer.converter"):
        logging.getLogger(_name).setLevel(logging.ERROR)


def read(path: Path) -> Iterator[Chunk]:
    for page_num, page in enumerate(extract_pages(str(path)), start=1):
        parts: list[str] = []
        for element in page:
            if isinstance(element, LTTextContainer):
                parts.append(element.get_text())
        text = "".join(parts).strip()
        if not text:
            continue
        yield Chunk(
            file_path=str(path),
            file_type="pdf",
            location=f"page={page_num}",
            text=text,
        )
