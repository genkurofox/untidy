"""--strict CLI flag: distinguish 'no findings' from 'couldn't read some files'."""
from __future__ import annotations

from pathlib import Path

from untidy.cli import main


def test_strict_returns_2_on_unreadable_file(tmp_path: Path):
    bad = tmp_path / "broken.json"
    bad.write_text("{not json")
    out = tmp_path / "r.csv"

    rc_lenient = main(["scan", str(bad), "--output", str(out)])
    # Without --strict: read error doesn't fail the run; no findings -> 0.
    assert rc_lenient == 0

    rc_strict = main(["scan", str(bad), "--output", str(out), "--strict"])
    assert rc_strict == 2


def test_strict_does_not_change_exit_when_no_errors(fixtures_dir: Path, tmp_path: Path):
    out = tmp_path / "r.csv"
    rc = main(["scan", str(fixtures_dir / "patients.csv"),
               "--output", str(out), "--strict"])
    # findings present, no read errors -> 1 as usual
    assert rc == 1
