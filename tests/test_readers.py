from pathlib import Path

from untidy.readers import csv_reader, excel_reader, sql_reader, text_reader


def test_csv_reader_yields_cells_with_headers(fixtures_dir: Path):
    chunks = list(csv_reader.read(fixtures_dir / "patients.csv"))
    assert any(c.column_header == "ssn" and c.text == "123-45-6789" for c in chunks)
    assert any(c.column_header == "first_name" and c.text == "John" for c in chunks)
    assert all(c.file_type == "csv" for c in chunks)


def test_csv_reader_skips_empty_cells(fixtures_dir: Path):
    chunks = list(csv_reader.read(fixtures_dir / "benign.csv"))
    assert all(c.text != "" for c in chunks)


def test_excel_reader(patients_xlsx: Path):
    chunks = list(excel_reader.read(patients_xlsx))
    assert any(c.column_header == "ssn" and c.text == "456-78-9012" for c in chunks)
    assert any(c.column_header == "full_name" and c.text == "Maria Garcia" for c in chunks)
    assert all(c.file_type == "xlsx" for c in chunks)
    assert all(c.location.startswith("sheet=Patients ") for c in chunks)


def test_sql_reader_extracts_string_literals(fixtures_dir: Path):
    chunks = list(sql_reader.read(fixtures_dir / "queries.sql"))
    texts = [c.text for c in chunks]
    assert "123-45-6789" in texts
    assert "4111-1111-1111-1111" in texts
    assert any("MRN 12345678" in t for t in texts)


def test_text_reader_line_numbers(tmp_path: Path):
    p = tmp_path / "sample.txt"
    p.write_text("one\ntwo\nthree\n")
    chunks = list(text_reader.read(p))
    assert [c.text for c in chunks] == ["one", "two", "three"]
    assert [c.location for c in chunks] == ["line=1", "line=2", "line=3"]
