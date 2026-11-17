"""[F007][S004] Q4.2 — uploaded receipts stay viewable after the container disk is wiped."""

from contextlib import contextmanager

import pytest
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import main
from app.models import AppUser, Branch, Receipt, Student

PNG_BYTES = b"\x89PNG\r\n\x1a\nzomate-proof"


def _seed(db):
    branch = Branch(name="TST", code="TST", address="Test")
    student = Student(full_name="Alice Wong", phone="91110001", branch=branch, hkid="A123456")
    db.add_all([branch, student])
    db.flush()
    receipt = Receipt(
        student_id=student.id,
        member_hkid="A123456",
        file_path="receipts/A123456/lost-proof.png",
        amount=500,
        source="RENEWAL",
        file_data=PNG_BYTES,
        content_type="image/png",
    )
    db.add(receipt)
    db.commit()
    return student, receipt


def test_uploads_static_falls_back_to_postgres_blob(db_session, monkeypatch, tmp_path):
    """Disk file is gone (redeploy) but /uploads still returns the stored bytes."""
    _student, receipt = _seed(db_session)

    @contextmanager
    def _test_session():
        yield db_session

    monkeypatch.setattr(main, "db_session", _test_session)
    uploads = main.UploadBlobStaticFiles(directory=str(tmp_path))
    res = uploads._blob_response(receipt.file_path)
    assert res.status_code == 200
    assert res.body == PNG_BYTES
    assert res.media_type == "image/png"


def test_uploads_static_returns_404_when_no_blob_or_file(db_session, monkeypatch, tmp_path):
    _student, receipt = _seed(db_session)
    receipt.file_data = None
    db_session.commit()

    @contextmanager
    def _test_session():
        yield db_session

    monkeypatch.setattr(main, "db_session", _test_session)
    uploads = main.UploadBlobStaticFiles(directory=str(tmp_path))
    with pytest.raises(StarletteHTTPException):
        uploads._blob_response(receipt.file_path)


def test_download_receipt_falls_back_to_blob(db_session):
    _student, receipt = _seed(db_session)
    admin = AppUser(username="ops", role="ADMIN", password_salt="", password_hash="")

    res = main.download_receipt(receipt_id=receipt.id, db=db_session, user=admin)
    assert res.body == PNG_BYTES
    assert res.media_type == "image/png"


def test_read_upload_blob_reads_disk_file(tmp_path, monkeypatch):
    """Fresh uploads mirror the just-saved file bytes into the receipt row."""
    rel = "receipts/A123456/new.png"
    (tmp_path / "receipts" / "A123456").mkdir(parents=True)
    (tmp_path / rel).write_bytes(PNG_BYTES)
    monkeypatch.setattr(main, "UPLOADS_DIR", tmp_path)

    data, media = main._read_upload_blob(rel)
    assert data == PNG_BYTES
    assert media == "image/png"
    assert main._read_upload_blob("receipts/A123456/missing.png") == (None, None)


def test_backfill_upload_blobs_copies_files_still_on_disk(db_session, tmp_path, monkeypatch):
    """Startup backfill gives pre-existing receipts a DB copy before a redeploy wipes disk."""
    _student, receipt = _seed(db_session)
    receipt.file_data = None
    receipt.content_type = None
    db_session.commit()
    (tmp_path / "receipts" / "A123456").mkdir(parents=True)
    (tmp_path / receipt.file_path).write_bytes(PNG_BYTES)
    monkeypatch.setattr(main, "UPLOADS_DIR", tmp_path)

    main._backfill_upload_blobs(db_session)
    db_session.refresh(receipt)
    assert receipt.file_data == PNG_BYTES
    assert receipt.content_type == "image/png"

