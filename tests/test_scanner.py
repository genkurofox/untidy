from pathlib import Path

from untidy.scanner import scan


def test_scan_finds_sensitive_data_in_fixtures(fixtures_dir: Path):
    findings = list(scan([fixtures_dir]))
    entities = {f.entity_type for f in findings}
    assert "SSN" in entities
    assert "CREDIT_CARD" in entities
    assert "EMAIL" in entities
    assert "PHONE_US" in entities
    assert "NAME_FROM_HEADER" in entities


def test_scan_ignores_benign_file(fixtures_dir: Path):
    findings = list(scan([fixtures_dir / "benign.csv"]))
    # benign.csv has no sensitive data; at most very low-confidence hits. Assert no high-confidence entities.
    high = [f for f in findings if f.confidence == "high"]
    assert high == []


def test_scan_respects_include_ext(fixtures_dir: Path):
    findings = list(scan([fixtures_dir], include_ext=[".sql"]))
    assert all(f.file_type == "sql" for f in findings)


def test_scan_no_mask_keeps_raw_values(fixtures_dir: Path):
    findings = list(scan([fixtures_dir / "patients.csv"], mask=False))
    ssns = [f.match_snippet for f in findings if f.entity_type == "SSN"]
    assert "123-45-6789" in ssns
