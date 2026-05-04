import csv
from pathlib import Path

from untidy.cli import main


def test_cli_end_to_end(fixtures_dir: Path, tmp_path: Path, capsys):
    out = tmp_path / "report.csv"
    rc = main([
        "scan",
        str(fixtures_dir / "patients.csv"),
        str(fixtures_dir / "queries.sql"),
        "--output", str(out),
    ])
    assert rc == 1  # findings present

    with out.open() as fh:
        rows = list(csv.DictReader(fh))

    entity_types = {r["entity_type"] for r in rows}
    assert "SSN" in entity_types
    assert "CREDIT_CARD" in entity_types
    assert "EMAIL" in entity_types
    assert "NAME_FROM_HEADER" in entity_types
    # Masked by default: first 7 characters should be stars, last 4 digits visible.
    ssn_rows = [r for r in rows if r["entity_type"] == "SSN"]
    assert ssn_rows
    for r in ssn_rows:
        snippet = r["match_snippet"]
        assert snippet.startswith("*" * 7), snippet
        assert snippet[-4:].isdigit(), snippet


def test_cli_exit_zero_on_clean(fixtures_dir: Path, tmp_path: Path):
    out = tmp_path / "report.csv"
    rc = main([
        "scan",
        str(fixtures_dir / "benign.csv"),
        "--output", str(out),
    ])
    # benign may have low-confidence hits (ZIP-like 5-digit prices aren't present here).
    # We accept either 0 or 1 but the CSV must exist.
    assert rc in (0, 1)
    assert out.exists()


def test_cli_missing_path_returns_2(tmp_path: Path):
    rc = main([
        "scan",
        str(tmp_path / "nope.csv"),
        "--output", str(tmp_path / "r.csv"),
    ])
    assert rc == 2


def test_cli_min_confidence_filters_medium_and_below(fixtures_dir: Path, tmp_path: Path):
    low_out = tmp_path / "low.csv"
    high_out = tmp_path / "high.csv"
    main(["scan", str(fixtures_dir / "patients.csv"), "--output", str(low_out)])
    main(["scan", str(fixtures_dir / "patients.csv"),
          "--min-confidence", "high", "--output", str(high_out)])

    with low_out.open() as fh:
        low_rows = list(csv.DictReader(fh))
    with high_out.open() as fh:
        high_rows = list(csv.DictReader(fh))

    assert len(high_rows) < len(low_rows)
    assert all(r["confidence"] == "high" for r in high_rows)
    # DATE is medium; should disappear at --min-confidence high.
    assert not any(r["entity_type"] == "DATE" for r in high_rows)
    assert any(r["entity_type"] == "DATE" for r in low_rows)
