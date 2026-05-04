from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .git_scanner import is_git_repo, scan_git_deleted
from .report import write_csv
from .scanner import DEFAULT_EXTS, scan


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="untidy",
        description="Offline scanner for sensitive data in CSV, Excel, T-SQL, PDF, DOCX, JSON, and text files.",
    )
    p.add_argument("--version", action="version", version=f"untidy {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)
    scan_cmd = sub.add_parser("scan", help="Scan paths for sensitive data")
    scan_cmd.add_argument("paths", nargs="+", type=Path, help="Files or directories to scan")
    scan_cmd.add_argument(
        "--output",
        type=Path,
        default=Path("untidy-findings.csv"),
        help="CSV report path (default: untidy-findings.csv)",
    )
    scan_cmd.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Glob pattern to exclude (repeatable)",
    )
    scan_cmd.add_argument(
        "--include-ext",
        default=",".join(DEFAULT_EXTS),
        help=f"Comma-separated extensions (default: {','.join(DEFAULT_EXTS)})",
    )
    scan_cmd.add_argument("--max-size-mb", type=int, default=200)
    scan_cmd.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high"],
        default="low",
        help="Drop findings below this confidence level (default: low = keep all)",
    )
    scan_cmd.add_argument(
        "--no-mask",
        action="store_true",
        help="Emit raw matches instead of masked values",
    )
    scan_cmd.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any file failed to read (don't conflate read errors with 'no findings')",
    )
    scan_cmd.add_argument("--verbose", action="store_true")

    git_cmd = sub.add_parser(
        "scan-git",
        help="Scan a git repository's history for sensitive data in deleted files",
    )
    git_cmd.add_argument("repo", type=Path, help="Path to the git repository")
    git_cmd.add_argument(
        "--output", type=Path, default=Path("untidy-findings.csv"),
    )
    git_cmd.add_argument(
        "--include-ext",
        default=",".join(DEFAULT_EXTS),
        help=f"Comma-separated extensions (default: {','.join(DEFAULT_EXTS)})",
    )
    git_cmd.add_argument("--max-size-mb", type=int, default=200)
    git_cmd.add_argument(
        "--max-commits",
        type=int,
        default=None,
        help="Cap the number of deletion events scanned",
    )
    git_cmd.add_argument(
        "--min-confidence",
        choices=["low", "medium", "high"],
        default="low",
    )
    git_cmd.add_argument("--no-mask", action="store_true")
    git_cmd.add_argument("--strict", action="store_true")
    git_cmd.add_argument("--verbose", action="store_true")

    return p


_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _parse_exts(raw: str) -> list[str]:
    return [
        e.strip() if e.strip().startswith(".") else f".{e.strip()}"
        for e in raw.split(",")
        if e.strip()
    ]


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    threshold = _CONFIDENCE_RANK[args.min_confidence]
    exts = _parse_exts(args.include_ext)
    errors: list[str] = []

    if args.cmd == "scan":
        for p in args.paths:
            if not p.exists():
                print(f"error: path does not exist: {p}", file=sys.stderr)
                return 2
        source = scan(
            roots=args.paths,
            include_ext=exts,
            excludes=args.exclude,
            max_size_mb=args.max_size_mb,
            mask=not args.no_mask,
            verbose=args.verbose,
            errors_out=errors,
        )
    elif args.cmd == "scan-git":
        if not args.repo.exists():
            print(f"error: path does not exist: {args.repo}", file=sys.stderr)
            return 2
        if not is_git_repo(args.repo):
            print(f"error: not a git repository: {args.repo}", file=sys.stderr)
            return 2
        source = scan_git_deleted(
            repo=args.repo,
            include_ext=tuple(exts),
            max_size_mb=args.max_size_mb,
            mask=not args.no_mask,
            verbose=args.verbose,
            max_commits=args.max_commits,
            errors_out=errors,
        )
    else:
        return 2

    findings = [f for f in source if _CONFIDENCE_RANK[f.confidence] >= threshold]

    count = write_csv(findings, args.output)
    print(f"wrote {count} finding(s) to {args.output}", file=sys.stderr)
    if errors:
        print(f"{len(errors)} file(s) had read errors", file=sys.stderr)
        if args.strict:
            return 2
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
