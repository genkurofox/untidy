from untidy.detectors import checksums, headers, patterns
from untidy.detectors.base import detect
from untidy.models import Chunk


def test_luhn_valid_test_pan():
    assert checksums.luhn_valid("4111-1111-1111-1111")
    assert checksums.luhn_valid("5500 0000 0000 0004")


def test_luhn_invalid():
    assert not checksums.luhn_valid("1234-5678-9012-3456")
    assert not checksums.luhn_valid("1111")  # too short


def test_ssn_valid():
    assert checksums.ssn_valid("123-45-6789")
    assert not checksums.ssn_valid("000-12-3456")
    assert not checksums.ssn_valid("666-12-3456")
    assert not checksums.ssn_valid("900-12-3456")
    assert not checksums.ssn_valid("123-00-6789")
    assert not checksums.ssn_valid("123-45-0000")


def test_routing_valid():
    # Known-valid routing number (Chase NY)
    assert checksums.routing_valid("021000021")
    assert not checksums.routing_valid("123456789")


def test_header_matcher():
    assert headers.entity_for_header("SSN") == "SSN"
    assert headers.entity_for_header("patient_ssn") == "SSN"
    assert headers.entity_for_header("First Name") == "NAME"
    assert headers.entity_for_header("DOB") == "DOB"
    assert headers.entity_for_header("MRN") == "MRN"
    assert headers.entity_for_header("zip_code") == "ZIP_CODE"
    assert headers.entity_for_header("price") is None


def test_detect_ssn_regex():
    c = Chunk(file_path="f", file_type="text", location="line=1",
              text="contact ssn 123-45-6789 today")
    findings = detect(c)
    assert any(f.entity_type == "SSN" for f in findings)


def test_detect_credit_card_luhn():
    c = Chunk(file_path="f", file_type="text", location="line=1",
              text="card 4111-1111-1111-1111")
    findings = detect(c)
    assert any(f.entity_type == "CREDIT_CARD" for f in findings)


def test_detect_rejects_bad_luhn():
    c = Chunk(file_path="f", file_type="text", location="line=1",
              text="number 1234-5678-9012-3456")
    findings = detect(c)
    assert not any(f.entity_type == "CREDIT_CARD" for f in findings)


def test_detect_header_triggers_name_finding():
    c = Chunk(file_path="f", file_type="csv", location="row=2 col=first_name",
              text="Alice", column_header="first_name")
    findings = detect(c)
    assert any(f.entity_type == "NAME_FROM_HEADER" for f in findings)


def test_detect_mrn_requires_header_context():
    plain = Chunk(file_path="f", file_type="text", location="line=1",
                  text="random 12345678 value")
    assert not any(f.entity_type == "MRN" for f in detect(plain))

    with_header = Chunk(file_path="f", file_type="csv", location="row=2 col=mrn",
                        text="12345678", column_header="mrn")
    assert any(f.entity_type == "MRN" for f in detect(with_header))


def test_detect_mrn_inline_keyword():
    # Comment-style text in SQL files — the documented ad-hoc case.
    c = Chunk(file_path="f", file_type="sql", location="line=1 (comment)",
              text="-- patient John Doe, MRN 12345678")
    findings = detect(c, mask=False)
    mrn = [f for f in findings if f.entity_type == "MRN"]
    assert len(mrn) == 1
    assert mrn[0].match_snippet == "12345678"
    assert mrn[0].detection_rule == "regex+inline_keyword"


def test_detect_mrn_inline_variants():
    for phrase in [
        "medical record 12345678",
        "medical record no. 12345678",
        "medical record number: 12345678",
        "patient_id=12345678",
        "patient id 12345678",
    ]:
        c = Chunk(file_path="f", file_type="text", location="l", text=phrase)
        assert any(f.entity_type == "MRN" for f in detect(c)), phrase


def test_detect_masks_by_default():
    c = Chunk(file_path="f", file_type="text", location="line=1",
              text="ssn 123-45-6789")
    f = [x for x in detect(c) if x.entity_type == "SSN"][0]
    assert "6789" in f.match_snippet
    assert "123" not in f.match_snippet


def test_detect_no_mask():
    c = Chunk(file_path="f", file_type="text", location="line=1",
              text="ssn 123-45-6789")
    f = [x for x in detect(c, mask=False) if x.entity_type == "SSN"][0]
    assert f.match_snippet == "123-45-6789"


def test_standalone_zip_not_in_value_detectors():
    # Standalone 5-digit ZIP detection was removed — too many FPs on order IDs.
    # ZIP columns still fire via the header heuristic (ZIP_CODE_FROM_HEADER).
    entities = {entry[0] for entry in patterns.VALUE_DETECTORS}
    assert "ZIP_CODE" not in entities


def test_zip_header_still_flags():
    c = Chunk(file_path="f", file_type="csv", location="row=2 col=zip",
              text="89501", column_header="zip")
    assert any(f.entity_type == "ZIP_CODE_FROM_HEADER" for f in detect(c))


def test_five_digit_id_is_not_flagged_as_zip():
    c = Chunk(file_path="f", file_type="csv", location="row=2 col=order_id",
              text="10001", column_header="order_id")
    assert [f.entity_type for f in detect(c)] == []


def test_credit_card_suppressed_for_non_pan_headers():
    for header in ["tx_id", "transaction_id", "order_id", "tracking_number",
                   "barcode", "upc", "sku"]:
        c = Chunk(file_path="f", file_type="csv", location="row=2",
                  text="4111-1111-1111-1111", column_header=header)
        assert not any(f.entity_type == "CREDIT_CARD" for f in detect(c)), header


def test_credit_card_still_fires_in_neutral_text():
    c = Chunk(file_path="f", file_type="text", location="line=1",
              text="card on file: 4111-1111-1111-1111")
    assert any(f.entity_type == "CREDIT_CARD" for f in detect(c))


def test_credit_card_still_fires_when_header_says_card():
    c = Chunk(file_path="f", file_type="csv", location="row=2 col=credit_card_number",
              text="4111-1111-1111-1111", column_header="credit_card_number")
    assert any(f.entity_type == "CREDIT_CARD" for f in detect(c))
