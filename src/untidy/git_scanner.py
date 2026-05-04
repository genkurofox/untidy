"""Scan a git repository's history for deleted files that may contain sensitive data.

Deleted files remain in git history forever. Someone can commit `patients.csv`,
realize the mistake, `git rm` it, and still have the content reachable via
``git log --all`` until the history is rewritten. This scanner surfaces those
historical versions so they can be remediated.

Strategy:
  1. Enumerate every deletion event across all refs (``--all --diff-filter=D``).
  2. For each ``(commit, path)`` pair, fetch the blob as it existed just before
     deletion (``git show <commit>^:<path>``).
  3. Write that blob to a temp file with the original extension, then reuse the
     same readers + detectors used for on-disk scanning.
  4. Rewrite each Finding's ``file_path`` and ``location`` to record the git
     origin (commit + original path), so the report is actionable.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterator, Optional

from .detectors.base import detect
from .models import Finding
from .scanner import READERS


def _git(repo: Path, *args: str, check: bool = True) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace')}"
        )
    return result.stdout


def is_git_repo(path: Path) -> bool:
    try:
        subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--git-dir"],
            capture_output=True,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def iter_deletions(
    repo: Path, include_ext: tuple[str, ...]
) -> Iterator[tuple[str, str]]:
    """Yield (deletion_commit_sha, deleted_path) for every deletion across all refs.

    Paths are filtered by extension here to avoid fetching blobs we'd skip anyway.
    """
    out = _git(
        repo,
        "log",
        "--all",
        "--diff-filter=D",
        "--name-only",
        "--pretty=format:%H",
    ).decode(errors="replace")

    exts = {e.lower() for e in include_ext}
    current_commit: Optional[str] = None
    seen: set[tuple[str, str]] = set()
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            continue
        if len(line) == 40 and all(c in "0123456789abcdef" for c in line):
            current_commit = line
            continue
        if current_commit is None:
            continue
        ext = "." + line.rsplit(".", 1)[-1].lower() if "." in line else ""
        if ext not in exts:
            continue
        key = (current_commit, line)
        if key in seen:
            continue
        seen.add(key)
        yield key


def _read_pre_deletion_blob(
    repo: Path, commit: str, path: str
) -> Optional[bytes]:
    """Content of `path` in the parent of `commit` — i.e. just before deletion."""
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"{commit}^:{path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def scan_git_deleted(
    repo: Path,
    include_ext: tuple[str, ...],
    max_size_mb: int = 200,
    mask: bool = True,
    verbose: bool = False,
    max_commits: Optional[int] = None,
) -> Iterator[Finding]:
    if not is_git_repo(repo):
        raise RuntimeError(f"not a git repository: {repo}")

    max_bytes = max_size_mb * 1024 * 1024
    processed = 0
    for commit, path in iter_deletions(repo, include_ext):
        if max_commits is not None and processed >= max_commits:
            break
        processed += 1

        blob = _read_pre_deletion_blob(repo, commit, path)
        if blob is None:
            if verbose:
                print(
                    f"skip (no parent or missing blob): {commit[:10]} {path}",
                    file=sys.stderr,
                )
            continue
        if len(blob) > max_bytes:
            if verbose:
                print(f"skip (too large): {commit[:10]} {path}", file=sys.stderr)
            continue

        suffix = Path(path).suffix.lower()
        reader = READERS.get(suffix)
        if reader is None:
            continue

        if verbose:
            print(f"scanning: {commit[:10]} {path}", file=sys.stderr)

        with tempfile.NamedTemporaryFile(
            prefix="untidy-git-", suffix=suffix, delete=False
        ) as tf:
            tf.write(blob)
            tmp_path = Path(tf.name)

        try:
            for chunk in reader(tmp_path):
                for finding in detect(chunk, mask=mask):
                    yield Finding(
                        file_path=f"git:{path}",
                        file_type=finding.file_type,
                        location=f"commit={commit[:10]} {finding.location}",
                        entity_type=finding.entity_type,
                        detection_rule=finding.detection_rule,
                        confidence=finding.confidence,
                        match_snippet=finding.match_snippet,
                        column_header=finding.column_header,
                    )
        except Exception as e:
            print(
                f"error scanning {commit[:10]} {path}: {e}",
                file=sys.stderr,
            )
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass
