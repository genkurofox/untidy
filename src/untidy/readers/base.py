from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterator

from ..models import Chunk

ReaderFn = Callable[[Path], Iterator[Chunk]]
