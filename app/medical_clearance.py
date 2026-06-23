"""[F001][S002]
Feature: Student Onboarding
Step: PAR-Q medical clearance status and file helpers
Logic: Compute pending/received/not_required; parse legacy health_notes; build admin API payloads.
"""

from __future__ import annotations

import json
import re
from typing import Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Student

MedicalClearanceStatus = Literal["not_required", "pending", "received"]

PARQ_LINE_RE = re.compile(r"PAR-Q JSON:\s*(\{.*\})\s*$", re.MULTILINE)


def parq_dict_any_yes(parq: dict) -> bool:
    return any(bool(v) for v in parq.values())


def compute_medical_clearance_status(*, parq_any_yes: bool, has_file: bool) -> MedicalClearanceStatus:
    if not parq_any_yes:
        return "not_required"
    return "received" if has_file else "pending"


def parse_parq_from_health_notes(notes: str | None) -> dict | None:
    """[F001][S002] Best-effort parse for legacy rows before parq_json column backfill."""
    if not notes:
        return None
    match = PARQ_LINE_RE.search(notes)
    if not match:
        return None
    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def legacy_had_medical_filename(notes: str | None) -> bool:
    if not notes:
        return False
    for line in notes.splitlines():
        if line.strip().startswith("Medical clearance file:"):
            return bool(line.split(":", 1)[1].strip())
    return False


def medical_clearance_payload(student: Student, file_url_fn) -> dict:
    """[F001][S002] Admin-facing health block for member detail."""
    parq: dict | None = None
    raw = getattr(student, "parq_json", None)
    if raw:
        try:
            parsed = json.loads(raw)
            parq = parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            parq = None
    if parq is None:
        parq = parse_parq_from_health_notes(student.health_notes)
    status = getattr(student, "medical_clearance_status", None) or "not_required"
    path = getattr(student, "medical_clearance_path", None)
    any_yes = parq_dict_any_yes(parq) if parq else False
    return {
        "parq": parq,
        "parq_any_yes": any_yes,
        "medical_clearance_status": status,
        "medical_clearance_path": path,
        "medical_clearance_url": file_url_fn(path) if path else None,
    }


def validate_medical_upload(file) -> None:
    """[F001][S002] PDF or image, max 3MB — mirrors register wizard rules."""
    from fastapi import HTTPException

    if not file or not getattr(file, "filename", None):
        raise HTTPException(status_code=400, detail="Medical clearance file is required.")
    content_type = (getattr(file, "content_type", None) or "").lower()
    ok_type = content_type.startswith("image/") or content_type == "application/pdf"
    if not ok_type:
        raise HTTPException(status_code=400, detail="請上傳 PDF 或圖片（JPEG、PNG、WebP、GIF）。")
    # Size checked in storage_service.save_upload via max_bytes argument.
