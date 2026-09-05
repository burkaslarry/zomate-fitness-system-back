"""[F001][S003] Unit tests for Fung Excel CSV column helpers."""

import io

from app.excel_csv_compat import (
    format_emergency_contact,
    is_fung_payment_headers,
    is_fung_student_headers,
    normalize_gender,
    parse_amount,
    parse_emergency_contact,
    parse_flexible_date,
    parse_installment_label,
    upload_bytes_to_csv_text,
)


def test_normalize_gender():
    assert normalize_gender("男") == "male"
    assert normalize_gender("女") == "female"
    assert normalize_gender("M") == "male"
    assert normalize_gender("F") == "female"
    assert normalize_gender("male") == "male"


def test_emergency_contact_roundtrip():
    assert parse_emergency_contact("Kwok Tak Shing (Dad)") == ("Kwok Tak Shing", "Dad")
    assert format_emergency_contact("A", "Mom") == "A (Mom)"


def test_parse_amount_and_installment():
    assert parse_amount("7,100.00") == 7100.0
    assert parse_installment_label("2/3 payment") == (2, 3)


def test_flexible_date():
    assert parse_flexible_date("1999/12/28").isoformat() == "1999-12-28"
    assert parse_flexible_date("2024-01-02").isoformat() == "2024-01-02"


def test_header_detect():
    assert is_fung_student_headers(["MemberCode", "Name", "Gender"])
    assert not is_fung_student_headers(["full_name", "phone"])
    assert is_fung_payment_headers(["電話號碼", "收費", "付款方法"])
    assert not is_fung_payment_headers(["student_phone", "amount"])


def test_xlsx_first_sheet_to_csv():
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "工作表1"
    ws.append(["Name", "Gender", "phone number"])
    ws.append(["Ada", "女", "9123 4567"])
    ws2 = wb.create_sheet("學生資料")
    ws2.append(["ignored"])
    buf = io.BytesIO()
    wb.save(buf)
    text = upload_bytes_to_csv_text(buf.getvalue(), "students.xlsx")
    assert "Name" in text and "Gender" in text
    assert "Ada" in text
    assert "ignored" not in text
