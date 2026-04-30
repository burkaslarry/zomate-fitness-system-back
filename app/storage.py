import os
from datetime import datetime
from pathlib import Path

from fastapi import HTTPException, UploadFile

from .config import settings


class FileStorageService:
    allowed_mime_by_suffix = {
        ".jpg": {"image/jpeg"},
        ".jpeg": {"image/jpeg"},
        ".png": {"image/png"},
        ".webp": {"image/webp"},
        ".pdf": {"application/pdf"},
    }
    max_bytes_by_kind = {
        "photos": 2 * 1024 * 1024,
        "receipts": 5 * 1024 * 1024,
    }

    def __init__(self, uploads_dir: Path | None = None) -> None:
        self.uploads_dir = (uploads_dir or settings.uploads_dir).resolve()
        self.uploads_dir.mkdir(parents=True, exist_ok=True)

    def save_upload(self, file: UploadFile, kind: str, hkid: str) -> str:
        suffix = Path(file.filename or "").suffix.lower()
        if suffix not in self.allowed_mime_by_suffix:
            raise HTTPException(status_code=400, detail="Only jpg/png/webp/pdf files are allowed.")
        if file.content_type not in self.allowed_mime_by_suffix[suffix]:
            raise HTTPException(status_code=400, detail="File MIME type does not match the allowed upload types.")

        max_bytes = self.max_bytes_by_kind.get(kind, 5 * 1024 * 1024)
        normalized_hkid = "".join(hkid.upper().split())
        safe_name = "".join(ch for ch in Path(file.filename or f"upload{suffix}").name if ch.isalnum() or ch in "._-")
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        relative_dir = Path(kind) / normalized_hkid
        out_dir = self.uploads_dir / relative_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        relative_path = relative_dir / f"{timestamp}-{safe_name}"
        out_path = self.uploads_dir / relative_path

        size = 0
        with out_path.open("wb") as out:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    out.close()
                    try:
                        out_path.unlink()
                    except OSError:
                        pass
                    raise HTTPException(status_code=413, detail="File is too large.")
                out.write(chunk)
        return str(relative_path).replace(os.sep, "/")
