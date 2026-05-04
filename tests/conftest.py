from __future__ import annotations

from pathlib import Path

import pytest
from openpyxl import Workbook

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def patients_xlsx(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build an xlsx fixture at test time so we don't commit binary files."""
    out = tmp_path_factory.mktemp("xlsx") / "patients.xlsx"
    wb = Workbook()
    ws = wb.active
    ws.title = "Patients"
    ws.append(
        ["patient_id", "full_name", "dob", "ssn", "phone", "email", "mrn"]
    )
    ws.append(
        ["P010", "Maria Garcia", "1988-02-19", "456-78-9012",
         "(415) 555-0123", "maria@example.com", "87654321"]
    )
    ws.append(
        ["P011", "Bob Lee", "1965-12-01", "567-89-0123",
         "415-555-0155", "bob.lee@example.org", "12348765"]
    )
    wb.save(out)
    return out
