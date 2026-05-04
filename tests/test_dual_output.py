"""--unmasked-output: emit a second CSV with raw values alongside the masked one."""
from __future__ import annotations

import csv
from pathlib import Path

from untidy.cli import main


def test_unmasked_output_writes_both_files(fixtures_dir: Path, tmp_path: Path):
    masked = tmp_path / "masked.csv"
    raw = tmp_path / "raw.csv"
    rc = main([
        "scan", str(fixtures_dir / "patients.csv"),
        "--output", str(masked),
        "--unmasked-output", str(raw),
    ])
    assert rc == 1
    assert masked.exists()
    assert raw.exists()

    with masked.open() as fh:
        masked_rows = list(csv.DictReader(fh))
    with raw.open() as fh:
        raw_rows = list(csv.DictReader(fh))

    # Same number of findings in both files.
    assert len(masked_rows) == len(raw_rows)

    # Masked report: SSN snippet must not contain leading SSN digits.
    masked_ssns = [r["match_snippet"] for r in masked_rows if r["entity_type"] == "SSN"]
    assert masked_ssns
    for s in masked_ssns:
        assert s.startswith("*"), s
        assert s[-4:].isdigit(), s

    # Raw report: SSN snippet has the actual fixture value.
    raw_ssns = [r["match_snippet"] for r in raw_rows if r["entity_type"] == "SSN"]
    assert "123-45-6789" in raw_ssns


def test_unmasked_output_rejects_same_path_as_output(fixtures_dir: Path, tmp_path: Path):
    out = tmp_path / "same.csv"
    rc = main([
        "scan", str(fixtures_dir / "patients.csv"),
        "--output", str(out),
        "--unmasked-output", str(out),
    ])
    assert rc == 2


def test_no_mask_makes_primary_output_unmasked(fixtures_dir: Path, tmp_path: Path):
    out = tmp_path / "out.csv"
    rc = main([
        "scan", str(fixtures_dir / "patients.csv"),
        "--output", str(out), "--no-mask",
    ])
    assert rc == 1
    with out.open() as fh:
        rows = list(csv.DictReader(fh))
    ssns = [r["match_snippet"] for r in rows if r["entity_type"] == "SSN"]
    assert "123-45-6789" in ssns
