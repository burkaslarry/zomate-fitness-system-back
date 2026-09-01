"""[F004][S002]
Unit tests: receipt upload accepts PDF/images; humanize RENEWAL labels.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from fastapi import HTTPException, UploadFile

from app.payment_records import humanize_payment_source_label
from app.storage import FileStorageService


def _upload(name: str, content: bytes, content_type: str) -> UploadFile:
    return UploadFile(filename=name, file=io.BytesIO(content), headers={"content-type": content_type})


def test_humanize_renewal_source() -> None:
    assert humanize_payment_source_label("RENEWAL") == "續會"
    assert humanize_payment_source_label("REGISTER") == "新登記"
    assert humanize_payment_source_label("[Category: Yoga 瑜珈] 補回第一期") == "Yoga 瑜珈 · 補回第一期"
    assert humanize_payment_source_label(None) == "收據"


def test_storage_accepts_png_and_pdf(tmp_path: Path) -> None:
    """[F004][S002] Receipt uploads must accept image and PDF; DB stores relative path."""
    service = FileStorageService(uploads_dir=tmp_path)

    png_bytes = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
        b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    png_path = service.save_upload(_upload("receipt.png", png_bytes, "image/png"), "receipts", "Z123456")
    assert png_path.endswith(".png")
    assert (tmp_path / png_path).is_file()
    assert (tmp_path / png_path).stat().st_size == len(png_bytes)

    pdf_bytes = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
    pdf_path = service.save_upload(_upload("slip.pdf", pdf_bytes, "application/pdf"), "receipts", "Z123456")
    assert pdf_path.endswith(".pdf")
    assert (tmp_path / pdf_path).is_file()
    assert "receipts/" in pdf_path.replace("\\", "/")


def test_storage_rejects_disallowed_type(tmp_path: Path) -> None:
    service = FileStorageService(uploads_dir=tmp_path)
    with pytest.raises(HTTPException) as exc:
        service.save_upload(_upload("note.txt", b"hello", "text/plain"), "receipts", "Z123456")
    assert exc.value.status_code == 400


def test_storage_rejects_mime_mismatch(tmp_path: Path) -> None:
    service = FileStorageService(uploads_dir=tmp_path)
    with pytest.raises(HTTPException) as exc:
        service.save_upload(_upload("fake.pdf", b"not-a-pdf", "text/plain"), "receipts", "Z123456")
    assert exc.value.status_code == 400
