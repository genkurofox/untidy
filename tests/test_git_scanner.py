from __future__ import annotations

import csv
import shutil
import subprocess
from pathlib import Path

import pytest

from untidy.cli import main
from untidy.git_scanner import scan_git_deleted


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo_with_deleted_sensitive(tmp_path: Path, fixtures_dir: Path) -> Path:
    """A freshly-built git repo with a sensitive CSV committed and then deleted."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "commit.gpgsign", "false")

    # Seed a benign file so the first commit has content that survives.
    (repo / "README.md").write_text("# test repo\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "initial")

    # Commit the sensitive file.
    shutil.copy(fixtures_dir / "patients.csv", repo / "patients.csv")
    _git(repo, "add", "patients.csv")
    _git(repo, "commit", "-q", "-m", "add patients")

    # Delete it in a later commit.
    _git(repo, "rm", "-q", "patients.csv")
    _git(repo, "commit", "-q", "-m", "remove patients")

    return repo


def test_scan_git_finds_sensitive_data_in_deleted_file(repo_with_deleted_sensitive: Path):
    findings = list(
        scan_git_deleted(
            repo=repo_with_deleted_sensitive,
            include_ext=(".csv", ".sql", ".xlsx", ".txt"),
            mask=False,
        )
    )
    assert findings, "expected findings from the deleted patients.csv"

    entities = {f.entity_type for f in findings}
    assert "SSN" in entities
    assert "NAME_FROM_HEADER" in entities

    # Location should carry the commit context so the user can find/purge it.
    assert all(f.location.startswith("commit=") for f in findings)
    # file_path should point at the original path in history, not the temp file.
    assert all(f.file_path == "git:patients.csv" for f in findings)


def test_scan_git_ignores_files_still_present(tmp_path: Path, fixtures_dir: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "commit.gpgsign", "false")
    shutil.copy(fixtures_dir / "patients.csv", repo / "patients.csv")
    _git(repo, "add", "patients.csv")
    _git(repo, "commit", "-q", "-m", "add patients (never deleted)")

    findings = list(
        scan_git_deleted(repo=repo, include_ext=(".csv",), mask=False)
    )
    assert findings == []


def test_scan_git_rejects_non_repo(tmp_path: Path):
    with pytest.raises(RuntimeError):
        list(
            scan_git_deleted(
                repo=tmp_path, include_ext=(".csv",), mask=False
            )
        )


def test_cli_scan_git_end_to_end(repo_with_deleted_sensitive: Path, tmp_path: Path):
    out = tmp_path / "report.csv"
    rc = main([
        "scan-git",
        str(repo_with_deleted_sensitive),
        "--output", str(out),
        "--no-mask",
    ])
    assert rc == 1
    with out.open() as fh:
        rows = list(csv.DictReader(fh))
    assert any(r["entity_type"] == "SSN" for r in rows)
    assert all(r["location"].startswith("commit=") for r in rows)


def test_cli_scan_git_missing_path_returns_2(tmp_path: Path):
    rc = main([
        "scan-git",
        str(tmp_path / "nope"),
        "--output", str(tmp_path / "r.csv"),
    ])
    assert rc == 2


def test_cli_scan_git_not_a_repo_returns_2(tmp_path: Path):
    rc = main([
        "scan-git",
        str(tmp_path),
        "--output", str(tmp_path / "r.csv"),
    ])
    assert rc == 2
