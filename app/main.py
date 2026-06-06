"""[F007][S001]
Feature: Backend platform (FastAPI & PostgreSQL)
Step: (see Logic)
Logic: FastAPI monolith: lifespan, CORS, REST plus WebSocket; domains F001 through F005.
"""

import asyncio
import base64
import calendar
import csv
import io
import json
import hashlib
import hmac
import os
import secrets
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import distinct, func, or_, select, text
from sqlalchemy.orm import Session, joinedload
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen.canvas import Canvas
import qrcode

from .config import settings
from .database import Base, engine, get_db
from .health_app import liveness_payload
from .keepalive import keepalive_loop
from .logutil import configure_logging, instance_id, log_event
from .register_public import router as register_public_router
from .timezone import HK, hk_calendar_date, now_hk
from .models import (
    ActivityLog,
    AppUser,
    Attendance,
    AuditLog,
    AuthSession,
    Branch,
    CategoryEnrollment,
    CheckinLog,
    Coach,
    Course,
    CourseCategory,
    CourseEnrollment,
    DeletedRecord,
    Expense,
    InstallmentPayment,
    InstallmentPlan,
    LessonLedgerEntry,
    Package,
    Receipt,
    RenewalRecord,
    Student,
    StudentPhoto,
    WhatsAppLog,
)
from .schemas import (
    BranchCreate,
    BranchUpdate,
    BranchOut,
    CheckinInput,
    CoachCreate,
    CoachEnrolledStudentOut,
    CoachOut,
    CoachTrialGrantBody,
    CoachUpdate,
    CourseCategoryCreate,
    CourseCategoryAdminUpdate,
    CourseAssignCoach,
    CourseCreate,
    CourseEnrollmentOut,
    CourseInstallmentMarkPaid,
    CourseOut,
    CourseReschedule,
    InstallmentSegmentPinOut,
    FaceIdCheckinInput,
    LoginInput,
    LoginSession,
    ManualLessonRedeemInput,
    ExpenseCreate,
    MemberCreate,
    MemberProspectDupCheck,
    MemberUpdate,
    PackageOut,
    RenewalCreate,
    StudentCategoryEnrollmentCreate,
    StudentOnboardCreate,
    StudentOut,
    StudentRegisterV1,
    TrialClassCreate,
    TrialPurchaseInput,
)
from .storage import FileStorageService

# -----------------------------------------------------------------------------
# Zomate Fitness — FastAPI service (zomate-fitness-system-back)
#
# REST + WebSocket; PostgreSQL ``zomate_fs_*``. Bearer auth ADMIN / CLERK / COACH（COACH：僅自用課程曆）；CORS。
#
# Inline feature registry (cross-reference README "Feature codes"):
#
#   Features F001:HealthAndProbes -- ``app/health_app.py``; GET /health, /api/health (no DB);
#                                   readiness GET /health/db, /api/health/db via SELECT 1.
#   Features F002:StructuredLogging -- ``app/logutil.py``; JSON-ish events + instance_id.
#   Features F003:TypedSettingsEnv -- ``app/config.py``; pydantic-settings mirrors Render/.env knobs.
#   Features F004:RenderKeepalive -- ``app/keepalive.py``; lifespan pings PUBLIC_BASE_URL/api/health.
#   Features F005:HongKongClock -- ``app/timezone.py``; attendances keyed on Asia/Hong_Kong date.
#   Features F006:SmsOtpAdapterSeam -- ``app/otp_sms.py``; mock OTP; Twilio TODO behind Protocol.
#   Features F007:QrRegistrationFlow -- ``app/register_public.py``, ``app/pin_util.py``;
#                                       POST /api/register/* (OTP then hashed PIN).
#   Features F008:StaffStudentOnboarding -- POST /api/v1/students/register; /api/onboarding; /api/members.
#   Features F009:ScheduledCourseAndPins -- POST /api/admin/courses; enrollment ``checkin_pin``.
#   Features F010:CheckInLedger -- POST /api/checkin; LessonLedger + Attendance de-dupe (HK calendar).
#   Features F011:CourseCategoryOps -- /api/admin/course-categories (soft-hide via is_deleted).
#   Features F012:CategoryEnrollmentFinance -- category enrollment POST + InstallmentPlan seeding hooks.
#   Features F013:CoachTrialQuota -- POST .../coach-trial-grant; ``coach_trial_quota_remaining``.
#   Features F014:FinanceReportsV1 -- GET /api/v1/reports/*; session-ledger payload uses ``entries``.
#   Features F015:AdminChromeFrontend -- Next.js shell (``components/backend-shell.tsx``); sidebar + pings.
#
# Swagger: /docs · ReDoc: /redoc · OpenAPI: /openapi.json
# -----------------------------------------------------------------------------

app = FastAPI(
    title="Zomate Fitness API",
    description="""
REST API + WebSocket；資料表前缀 ``zomate_fs_*``（PostgreSQL）。

**Swagger UI：** [`/docs`](/docs) · **ReDoc：** [`/redoc`](/redoc) · **OpenAPI JSON：** [`/openapi.json`](/openapi.json)

多數受保護路由需在 **Authorize** 貼上 `Bearer <token>`（由 `POST /api/auth/login` 取得）。
""",
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    swagger_ui_parameters={"persistAuthorization": True},
    openapi_tags=[
        {
            "name": "health",
            "description": "Liveness / readiness；**毋須** Authorization。",
        },
    ],
)

_AGENT_DEBUG_LOG = "/Users/larrylo/SourceProject/zomate-fitness/.cursor/debug-195967.log"


def _agent_dbg(hypothesis_id: str, location: str, message: str, data: dict) -> None:
    if os.environ.get("AGENT_DEBUG", "").lower() not in ("1", "true", "yes"):
        return
    try:
        payload = {
            "sessionId": "195967",
            "hypothesisId": hypothesis_id,
            "location": location,
            "message": message,
            "data": data,
            "timestamp": int(datetime.utcnow().timestamp() * 1000),
        }
        with open(_AGENT_DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except OSError:
        pass


@app.get("/", include_in_schema=False)
def root_redirect_to_docs() -> RedirectResponse:
    """Landing：導向 Swagger UI。"""
    return RedirectResponse(url="/docs")

def _cors_origins_from_env() -> list[str]:
    return settings.cors_origins


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins_from_env(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOADS_DIR = settings.uploads_dir.resolve()
ACTIVE_MEMBER_DAYS = settings.active_member_days
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(UPLOADS_DIR)), name="uploads")
storage_service = FileStorageService(UPLOADS_DIR)
app.include_router(register_public_router)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "http_error", "message": str(exc.detail), "details": None},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"error": "validation_error", "message": "Request validation failed.", "details": exc.errors()},
    )


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._connections:
            self._connections.remove(websocket)

    async def broadcast_json(self, payload: dict) -> None:
        disconnected: list[WebSocket] = []
        for connection in self._connections:
            try:
                await connection.send_text(json.dumps(payload))
            except Exception:
                disconnected.append(connection)
        for connection in disconnected:
            self.disconnect(connection)


manager = ConnectionManager()

# CF08: Authentication and deletion baseline.
# Steps:
# 01. 使用 PBKDF2 + secure random salt 做 password hash 與驗證
# 02. 每次 login 建立有時效的 session token，落在 AuthSession
# 03. get_current_user / require_* 透過依賴注入（ADMIN／CLERK 後台全權；COACH 見 ``require_staff_for_coach_routes`` + slug 對應教練列）


def _hash_password(password: str, salt_hex: str) -> str:
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        180_000,
    )
    return key.hex()


def _new_session_token() -> str:
    return secrets.token_urlsafe(32)


def _make_password_record(password: str) -> tuple[str, str]:
    salt_hex = secrets.token_hex(16)
    return salt_hex, _hash_password(password, salt_hex)


def _verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    return hmac.compare_digest(_hash_password(password, salt_hex), expected_hash)


def _get_active_rows(db: Session, entity: str, id_field):
    subq = db.query(DeletedRecord.entity_id).filter(DeletedRecord.entity_type == entity)
    return db.query(id_field).filter(~id_field.in_(subq))


def _is_deleted(db: Session, entity_type: str, entity_id: int) -> bool:
    return (
        db.query(DeletedRecord)
        .filter(
            DeletedRecord.entity_type == entity_type,
            DeletedRecord.entity_id == entity_id,
        )
        .first()
        is not None
    )


def _record_soft_delete(db: Session, entity_type: str, entity_id: int, actor: AppUser) -> None:
    if _is_deleted(db, entity_type, entity_id):
        return
    db.add(
        DeletedRecord(
            entity_type=entity_type,
            entity_id=entity_id,
            deleted_by_username=actor.username,
            deleted_hard=False,
        )
    )


def _build_qr_code_pdf_bytes(label: str, payload: str) -> bytes:
    qr_img = qrcode.make(payload)
    qr_buffer = io.BytesIO()
    qr_img.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)

    packet = io.BytesIO()
    canvas = Canvas(packet, pagesize=A4)
    width, _ = A4
    canvas.setFont("Helvetica-Bold", 16)
    canvas.drawString(40, 800, "Zomate Fitness — QR Paper (Print-out)")
    canvas.setFont("Helvetica", 11)
    canvas.drawString(40, 776, "Print this page and display at reception / gym floor.")
    canvas.setFont("Helvetica", 10)
    canvas.drawString(40, 752, f"Purpose: {label}")
    canvas.drawImage(
        ImageReader(qr_buffer),
        (width - 260) / 2,
        290,
        width=260,
        height=260,
        preserveAspectRatio=True,
        mask="auto",
    )
    canvas.setFont("Helvetica", 9)
    canvas.drawString(40, 56, "Scan with mobile — Zomate Fitness check-in / onboarding.")
    canvas.drawString(40, 42, "A4 printable layout · QR for counter display.")
    canvas.showPage()
    canvas.save()
    return packet.getvalue()


def _seed_default_users(db: Session) -> None:
    # CF09:CoachDemoAccount — demo 身份：coachdemo／COACH 只可用「教練曆」（前端限 /coach/calendar）；worker／CLERK 仍為後台職員。
    users = [
        ("masterzoe", "12345678", "ADMIN"),
        ("worker", "12347890", "CLERK"),
        ("coachdemo", "12347890", "COACH"),
    ]
    for username, password, role in users:
        row = db.query(AppUser).filter(AppUser.username == username).first()
        if row:
            row.role = role
            continue
        salt, pwd = _make_password_record(password)
        db.add(AppUser(username=username, role=role, password_salt=salt, password_hash=pwd))


def _parse_auth_header(auth_header: str | None) -> str | None:
    if not auth_header:
        return None
    if not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    return token if token else None


def get_current_user(
    Authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> AppUser:
    token = _parse_auth_header(Authorization)
    if token is None:
        raise HTTPException(status_code=401, detail="Missing auth token.")
    session = (
        db.query(AuthSession, AppUser)
        .join(AppUser, AppUser.id == AuthSession.user_id)
        .filter(AuthSession.token == token)
        .first()
    )
    if not session:
        raise HTTPException(status_code=401, detail="Invalid auth token.")
    auth_session = session[0]
    user = session[1]
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled.")
    if auth_session.expires_at <= datetime.utcnow():
        db.delete(auth_session)
        db.commit()
        raise HTTPException(status_code=401, detail="Session expired.")
    return user


def _alnum_slug(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


def _login_role_for_response(user: AppUser) -> str:
    """Map DB ``zomate_fs_users.role`` to API contract: ADMIN | CLERK | COACH."""
    r = (user.role or "").strip().upper()
    if r == "ADMIN":
        return "ADMIN"
    if r == "COACH":
        return "COACH"
    return "CLERK"


def require_admin_or_clerk(user: AppUser = Depends(get_current_user)) -> AppUser:
    """後台職員（不含 COACH）；COACH 帳號不可用依賴此注入的路由。"""
    if user.role not in {"ADMIN", "CLERK"}:
        raise HTTPException(status_code=403, detail="Role not allowed.")
    return user


def require_staff_for_coach_routes(user: AppUser = Depends(get_current_user)) -> AppUser:
    """`/api/coach/courses*` — ADMIN／CLERK 全 coach_id；COACH 僅可查與 slug 對應之教練列。"""
    if user.role not in {"ADMIN", "CLERK", "COACH"}:
        raise HTTPException(status_code=403, detail="Role not allowed.")
    return user


def _coach_user_may_access_coach_row(db: Session, user: AppUser, coach: Coach | None) -> bool:
    if user.role != "COACH":
        return True
    if not coach:
        return False
    us = _alnum_slug(user.username)
    fs = _alnum_slug(coach.full_name)
    if not us or not fs:
        return False
    return us in fs or fs in us


def require_admin(user: AppUser = Depends(get_current_user)) -> AppUser:
    if user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only ADMIN allowed.")
    return user


def log_whatsapp(db: Session, student: Student, recipient: str, message: str) -> None:
    log = WhatsAppLog(student_id=student.id, recipient=recipient, message=message)
    db.add(log)


# TODO [F005][S003]
# Feature: Balance Sync & Integrations
# Step: WhatsApp balance / renewal reminder
# Logic: Add a scheduled reminder job for low remaining paid lessons and upcoming
#        installment due dates. Do not remind for unpaid future PIN tranches until
#        staff marks that installment `paid`; use an idempotency key such as
#        student_id + course_id + reminder_type + HK business date.


# [F009][S002]
# Feature: Scheduled course & enrollment PINs
# Step: Allocate ``checkin_pin`` unique on this course (no two students share) and
#       unique per student across all enrollments so PIN resolution is unambiguous.
def allocate_enrollment_pin(
    db: Session,
    course_id: int,
    student_id: int,
    *,
    avoid_pins: frozenset[str] | None = None,
) -> str:
    """Allocate a PIN unique among this course, this student's rows, and any ``avoid_pins`` (same txn, pre-insert)."""
    reserved = frozenset(avoid_pins or ())
    peers_course = db.query(CourseEnrollment).filter(CourseEnrollment.course_id == course_id).all()
    peers_student = db.query(CourseEnrollment).filter(CourseEnrollment.student_id == student_id).all()
    for _ in range(200):
        pin = f"{secrets.randbelow(90000) + 10000}"
        if pin in reserved:
            continue
        if any(_enrollment_matches_class_pin(e, pin) for e in peers_course):
            continue
        if any(_enrollment_matches_class_pin(e, pin) for e in peers_student):
            continue
        return pin
    raise HTTPException(status_code=500, detail="Could not allocate class PIN.")


def _lesson_segment_ranges(total_lessons: int, n_segments: int) -> list[tuple[int, int]]:
    """Inclusive 1-based lesson indices per installment (split remainder across first tranches)."""
    tl = max(1, total_lessons)
    n = max(1, min(5, n_segments))
    if n == 1:
        return [(1, tl)]
    remainder = tl % n
    base = tl // n
    sizes = [base + (1 if i < remainder else 0) for i in range(n)]
    out: list[tuple[int, int]] = []
    cur = 1
    for sz in sizes:
        out.append((cur, cur + sz - 1))
        cur += sz
    return out


def _parse_segment_pins_json(raw: str | None) -> list[InstallmentSegmentPinOut]:
    """[F002][S001] Deserialize ``CourseEnrollment.segment_pins_json`` for API responses."""
    if not raw:
        return []
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(rows, list):
        return []
    out: list[InstallmentSegmentPinOut] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            ino = int(row["installment_no"])
            pr = row.get("paid")
            if pr is None:
                paid_bool = ino <= 1
            else:
                paid_bool = bool(pr)
            out.append(
                InstallmentSegmentPinOut(
                    installment_no=ino,
                    lesson_from=int(row["lesson_from"]),
                    lesson_to=int(row["lesson_to"]),
                    pin=str(row["pin"]).strip(),
                    paid=paid_bool,
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out


def _enrollment_matches_class_pin(enr: CourseEnrollment, pin: str) -> bool:
    """True if ``pin`` matches primary enrollment PIN or any installment-segment PIN."""
    p = pin.strip()
    if enr.checkin_pin == p:
        return True
    raw = getattr(enr, "segment_pins_json", None)
    if not raw:
        return False
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        return False
    if not isinstance(rows, list):
        return False
    for row in rows:
        if isinstance(row, dict) and str(row.get("pin", "")).strip() == p:
            return True
    return False


def _segment_paid_for_matched_pin(enr: CourseEnrollment, pin: str) -> bool:
    """[F003][S002]
    Segment PIN must belong to an installment marked paid (except legacy rows: missing paid → installment 1 only).
    Logic: Scheduled package multi-PIN gated until staff marks installments collected via PATCH.
    """
    p = pin.strip()
    raw = getattr(enr, "segment_pins_json", None)
    if not raw:
        return True
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        return True
    if not isinstance(rows, list) or len(rows) == 0:
        return True

    seg: dict | None = None
    for row in rows:
        if isinstance(row, dict) and str(row.get("pin", "")).strip() == p:
            seg = row
            break
    if seg is None and enr.checkin_pin == p:
        seg = next((r for r in rows if isinstance(r, dict) and int(r.get("installment_no") or 0) == 1), None)
    if seg is None or not isinstance(seg, dict):
        return False

    ino = int(seg.get("installment_no") or 0)
    pr = seg.get("paid")
    if pr is None:
        return ino <= 1
    return bool(pr)


def _add_calendar_months(d: date, months: int) -> date:
    y, month = d.year, d.month + months
    while month > 12:
        y += 1
        month -= 12
    while month < 1:
        y -= 1
        month += 12
    last = calendar.monthrange(y, month)[1]
    return date(y, month, min(d.day, last))


def _membership_expiry_iso(package_sessions: int) -> str:
    """Match ``computeMembershipExpiryIso`` (10→+3 months, 30→+6 months, from today)."""
    start = datetime.utcnow().date()
    months_add = 3 if package_sessions == 10 else 6
    end_d = _add_calendar_months(start, months_add)
    dt = datetime(end_d.year, end_d.month, end_d.day, 12, 0, 0, tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _register_v1_health_notes(payload: StudentRegisterV1) -> str:
    parts = [
        f"HKID: {payload.hkid.strip()}",
        f"Emergency: {payload.emergency_contact_name.strip()} / {payload.emergency_contact_phone.strip()}",
        f"Form type: {payload.form_type}",
        "Digital signature (step 3): canvas image saved",
        f"PAR-Q JSON: {json.dumps(payload.parq.model_dump(), ensure_ascii=False)}",
    ]
    em = (payload.email or "").strip()
    if em:
        parts.insert(2, f"Email: {em}")
    clr = (payload.medical_clearance_file_name or "").strip()
    if clr:
        parts.append(f"Medical clearance file: {clr}")
    rn = (payload.renewal_notes or "").strip()
    if rn:
        parts.append(f"Renewal notes: {rn}")
    return "\n".join(parts)


def _active_branches_filter():
    return ~Branch.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "branches"))


def allocate_branch_code(db: Session, preferred: str | None, name: str) -> str:
    raw = (preferred or "").strip().upper()
    if not raw:
        ascii_part = "".join(ch for ch in name.upper() if ch.isalnum())[:12]
        raw = ascii_part or f"BR{secrets.randbelow(9000) + 1000}"
    raw = raw[:32]
    if not db.query(Branch).filter(Branch.code == raw).filter(_active_branches_filter()).first():
        return raw
    for i in range(2, 100):
        candidate = f"{raw[:28]}{i}"
        if not db.query(Branch).filter(Branch.code == candidate).filter(_active_branches_filter()).first():
            return candidate
    raise HTTPException(status_code=409, detail="Branch code already exists.")


def normalize_hkid(raw: str) -> str:
    return "".join((raw or "").upper().split())


def normalize_hk_phone_local_eight(raw: str | None) -> str | None:
    """香港手機號：庫入面用 8 位數字；接受 +852 / 852 前綴或淨填 8 位。"""
    digits = "".join(ch for ch in (raw or "") if ch.isdigit())
    if len(digits) == 11 and digits.startswith("852"):
        tail = digits[3:]
        return tail if len(tail) == 8 else None
    if len(digits) == 8:
        return digits
    return None


def _hk_phone_lookup_variants(local_eight: str) -> list[str]:
    """比對資料庫內現有紀錄可能存 8 位、+852 或 852 前置。"""
    return [local_eight, f"+852{local_eight}", f"852{local_eight}"]


def _normalize_student_csv_name(name: str | None) -> str:
    """CSV 學員比對：去頭尾空白後 casefold，須與電話同時吻合才更新。"""
    return (name or "").strip().casefold()


def get_student_by_hkid_or_404(db: Session, hkid: str) -> Student:
    normalized = normalize_hkid(hkid)
    student = db.query(Student).filter(Student.hkid == normalized).first()
    if student is None or _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Member not found.")
    return student


def _student_from_trial_class_payload(db: Session, payload: TrialClassCreate) -> Student:
    deleted_ids_sq = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")
    if payload.student_id is not None:
        st = db.query(Student).filter(~Student.id.in_(deleted_ids_sq), Student.id == payload.student_id).first()
        if st is None:
            raise HTTPException(status_code=404, detail="Student not found.")
        return st
    ph = (payload.student_phone or "").strip()
    if ph:
        local = normalize_hk_phone_local_eight(ph)
        if not local:
            raise HTTPException(
                status_code=400,
                detail="電話須為香港 8 位手機號碼（請填 +852xxxxxxxx 或只填八位數字）。",
            )
        variants = _hk_phone_lookup_variants(local)
        st = db.query(Student).filter(~Student.id.in_(deleted_ids_sq), Student.phone.in_(variants)).first()
        if st is None:
            raise HTTPException(status_code=404, detail="找不到此電話的學員。")
        return st
    hk = (payload.member_hkid or "").strip()
    if hk:
        return get_student_by_hkid_or_404(db, hk)
    raise HTTPException(status_code=400, detail="缺少學員識別。")


def _resolve_active_course_category(db: Session, category_id: int | None) -> CourseCategory:
    """[F011][S001] Resolve an enabled course category for trial / renewal flows."""
    if category_id is not None:
        row = db.get(CourseCategory, category_id)
        if row is None or row.is_deleted or not row.is_active:
            raise HTTPException(status_code=400, detail="Invalid course_category_id.")
        return row
    row = (
        db.query(CourseCategory)
        .filter(CourseCategory.is_active.is_(True), CourseCategory.is_deleted.is_(False))
        .order_by(CourseCategory.id.asc())
        .first()
    )
    if row is None:
        raise HTTPException(status_code=500, detail="course_categories 未初始化，請聯絡管理員。")
    return row


def _trial_records_from_audit(db: Session, student_id: int) -> list[dict]:
    """[F002][S001] Trial history stored in audit logs after dropping zomate_fs_trial_classes."""
    rows = (
        db.query(AuditLog)
        .filter(
            AuditLog.student_id == student_id,
            AuditLog.action.in_(("trial_class_create", "coach_trial_quota_grant")),
        )
        .order_by(AuditLog.created_at.desc())
        .limit(200)
        .all()
    )
    coach_ids = [r.coach_id for r in rows if r.coach_id is not None]
    coaches = {c.id: c.full_name for c in db.query(Coach).filter(Coach.id.in_(coach_ids)).all()} if coach_ids else {}
    branch_ids: list[int] = []
    for row in rows:
        try:
            detail = json.loads(row.detail or "{}")
        except json.JSONDecodeError:
            detail = {}
        bid = detail.get("branch_id")
        if isinstance(bid, int):
            branch_ids.append(bid)
    branches = {b.id: b.name for b in db.query(Branch).filter(Branch.id.in_(branch_ids)).all()} if branch_ids else {}
    out: list[dict] = []
    for row in rows:
        try:
            detail = json.loads(row.detail or "{}")
        except json.JSONDecodeError:
            detail = {}
        cat_id = detail.get("course_category_id")
        cat_name = detail.get("course_category_name")
        if cat_id and not cat_name:
            cat = db.get(CourseCategory, cat_id)
            cat_name = cat.name if cat else None
        branch_id = detail.get("branch_id")
        out.append(
            {
                "id": row.id,
                "type": detail.get(
                    "type",
                    "coach_quota_1" if row.action == "coach_trial_quota_grant" else "TRIAL",
                ),
                "coach_id": row.coach_id or detail.get("coach_id"),
                "coach_name": coaches.get(row.coach_id) if row.coach_id is not None else None,
                "branch_id": branch_id,
                "branch_name": branches.get(branch_id) if isinstance(branch_id, int) else None,
                "course_category_id": cat_id,
                "course_category_name": cat_name,
                "trial_kind_id": cat_id,
                "trial_kind_label_zh": cat_name,
                "class_date": detail.get("class_date"),
                "note": detail.get("note"),
                "created_at": row.created_at.isoformat(),
            }
        )
    return out


def _enrolled_students_for_coaches(db: Session, coach_ids: list[int]) -> dict[int, list[CoachEnrolledStudentOut]]:
    """[F002][S001]
    Feature: Course Entry & Automation
    Step: Admin coach grid — list students enrolled in any course taught by each coach.
    Logic: Distinct (coach_id, student_id) via ``Course`` × ``CourseEnrollment`` × ``Student``.
    """
    if not coach_ids:
        return {}
    rows = (
        db.query(Course.coach_id, Student.id, Student.full_name, Student.phone)
        .join(CourseEnrollment, CourseEnrollment.course_id == Course.id)
        .join(Student, Student.id == CourseEnrollment.student_id)
        .filter(Course.coach_id.in_(coach_ids))
        .order_by(Course.coach_id, Student.full_name, Student.id)
        .all()
    )
    seen: dict[int, set[int]] = {}
    out: dict[int, list[CoachEnrolledStudentOut]] = {}
    for cid, sid, name, phone in rows:
        bucket = seen.setdefault(cid, set())
        if sid in bucket:
            continue
        bucket.add(sid)
        out.setdefault(cid, []).append(
            CoachEnrolledStudentOut(id=int(sid), full_name=name, phone=phone or "")
        )
    return out


def coach_row_to_out(
    db: Session,
    coach: Coach,
    *,
    enrolled_students: list[CoachEnrolledStudentOut] | None = None,
) -> CoachOut:
    bn: str | None = None
    if coach.branch_id is not None:
        br = db.get(Branch, coach.branch_id)
        if br is not None and not _is_deleted(db, "branches", br.id):
            bn = br.name
    return CoachOut(
        id=coach.id,
        full_name=coach.full_name,
        phone=coach.phone,
        specialty=coach.specialty,
        active=coach.active,
        branch_id=coach.branch_id,
        branch_name=bn,
        hire_date=coach.hire_date,
        created_at=coach.created_at,
        enrolled_students=list(enrolled_students or ()),
    )


def _file_url(relative_path: str | None) -> str | None:
    if not relative_path:
        return None
    path = f"/uploads/{relative_path}"
    public_base = settings.public_base_url.strip().rstrip("/")
    return f"{public_base}{path}" if public_base else path


def _signature_relative_path(stored: str | None) -> str | None:
    """Normalize legacy ``/uploads/...`` values to storage-relative paths."""
    if not stored:
        return None
    value = stored.strip()
    if value.startswith("/uploads/"):
        return value[len("/uploads/") :]
    if value.startswith("uploads/"):
        return value[len("uploads/") :]
    return value or None


def _signature_image_for_member(student: Student) -> str | None:
    """[F001][S004] Prefer PostgreSQL blob; fall back to local disk for dev uploads."""
    blob = getattr(student, "signature_image_blob", None)
    if blob:
        encoded = base64.b64encode(blob).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    relative_path = _signature_relative_path(student.signature_image_url)
    if relative_path and (UPLOADS_DIR / relative_path).is_file():
        return _file_url(relative_path)
    return None


def _save_signature_image(data_url: str, student_id: int) -> tuple[str, bytes]:
    """[F001][S004] Persist canvas signature PNG; return relative path + raw bytes for DB blob."""
    prefix = "data:image/png;base64,"
    raw = data_url.strip()
    if not raw.startswith(prefix):
        raise HTTPException(status_code=400, detail="Signature must be a PNG canvas data URL.")
    try:
        payload = base64.b64decode(raw[len(prefix) :], validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid signature image data.") from exc
    if len(payload) > 1_000_000:
        raise HTTPException(status_code=413, detail="Signature image is too large.")
    relative_dir = f"signatures/{student_id}"
    out_dir = UPLOADS_DIR / relative_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = f"sig_{student_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}.png"
    relative_path = f"{relative_dir}/{filename}"
    try:
        (UPLOADS_DIR / relative_path).write_bytes(payload)
    except OSError:
        pass
    return relative_path, payload


def _apply_signature_image(student: Student, data_url: str) -> None:
    relative_path, payload = _save_signature_image(data_url, student.id)
    student.signature_image_url = relative_path
    student.signature_image_blob = payload


def _save_upload_file(file: UploadFile, kind: str, hkid: str, max_bytes: int) -> str:
    return storage_service.save_upload(file, kind, hkid)


def _is_active_member(db: Session, student_id: int) -> bool:
    cutoff = datetime.utcnow() - timedelta(days=ACTIVE_MEMBER_DAYS)
    return (
        db.query(CheckinLog.id)
        .filter(CheckinLog.student_id == student_id, CheckinLog.created_at >= cutoff)
        .first()
        is not None
    )


def _member_package_status(db: Session, student_id: int) -> str:
    """[F001][S003]
    Feature: Student Onboarding
    Step: Admin member list package status
    Logic: Summarize category/course enrollments into a compact roster label.
    """
    active_category_count = (
        db.query(func.count(CategoryEnrollment.id))
        .filter(CategoryEnrollment.student_id == student_id, CategoryEnrollment.status == "active")
        .scalar()
        or 0
    )
    scheduled_course_count = (
        db.query(func.count(CourseEnrollment.id))
        .filter(CourseEnrollment.student_id == student_id)
        .scalar()
        or 0
    )
    if active_category_count and scheduled_course_count:
        return f"Active package + {scheduled_course_count} scheduled course(s)"
    if active_category_count:
        return "Active package"
    if scheduled_course_count:
        return f"{scheduled_course_count} scheduled course(s)"
    return "No active package"


def _student_last_checkin_iso(db: Session, student_id: int) -> str | None:
    """[F001][S003] Latest check-in timestamp for admin roster context."""
    last_at = (
        db.query(func.max(CheckinLog.created_at))
        .filter(CheckinLog.student_id == student_id)
        .scalar()
    )
    return last_at.isoformat() if last_at else None


def student_to_member_dict(db: Session, student: Student) -> dict:
    """[F001][S003]
    Member dict for admin / public profile. Sign-in PINs are **per course enrollment** only.
    """
    trial_q = getattr(student, "coach_trial_quota_remaining", 1)
    return {
        "id": student.id,
        "hkid": student.hkid,
        "full_name": student.full_name,
        "phone": student.phone,
        "email": student.email,
        "date_of_birth": student.date_of_birth.isoformat() if student.date_of_birth else None,
        "emergency_contact_name": student.emergency_contact_name,
        "emergency_contact_phone": student.emergency_contact_phone,
        "lesson_balance": _lesson_balance_sum(db, student.id),
        "coach_trial_quota_remaining": int(trial_q),
        "photo_path": student.photo_path,
        "photo_url": _file_url(student.photo_path),
        "signature_image_url": _signature_image_for_member(student),
        "used_mobile_number": student.used_mobile_number,
        "is_active": _is_active_member(db, student.id),
        "current_course_package_status": _member_package_status(db, student.id),
        "last_checkin_at": _student_last_checkin_iso(db, student.id),
        "created_at": student.created_at.isoformat(),
    }


def student_to_student_out(db: Session, student: Student) -> StudentOut:
    """[F007][S002] API model includes ``lesson_balance`` computed from ``zomate_fs_lesson_ledger`` (not a table column)."""
    return StudentOut(
        id=student.id,
        full_name=student.full_name,
        hkid=student.hkid,
        phone=student.phone,
        email=student.email,
        date_of_birth=student.date_of_birth,
        emergency_contact_name=student.emergency_contact_name,
        emergency_contact_phone=student.emergency_contact_phone,
        health_notes=student.health_notes,
        disclaimer_accepted=student.disclaimer_accepted,
        photo_path=student.photo_path,
        signature_image_url=_signature_image_for_member(student),
        lesson_balance=_lesson_balance_sum(db, student.id),
        face_id_external=student.face_id_external,
        created_at=student.created_at,
    )


def _course_checkin_pins_for_student(db: Session, student: Student) -> list[dict]:
    rows = (
        db.query(CourseEnrollment, Course, Branch, Coach)
        .join(Course, CourseEnrollment.course_id == Course.id)
        .join(Branch, Course.branch_id == Branch.id)
        .outerjoin(Coach, Coach.id == Course.coach_id)
        .filter(CourseEnrollment.student_id == student.id)
        .filter(~Course.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "courses")))
        .all()
    )
    return [
        {
            "course_id": course.id,
            "course_title": course.title,
            "branch_name": branch.name,
            "coach_name": (coach.full_name if coach else None) or "—",
            "scheduled_start": course.scheduled_start.isoformat(),
            "series_end_date": course.series_end_date.isoformat() if course.series_end_date else None,
            "checkin_pin": enr.checkin_pin,
            "installment_segments": [s.model_dump() for s in _parse_segment_pins_json(enr.segment_pins_json)],
        }
        for enr, course, branch, coach in rows
    ]


def _installment_plan_seed_rows(db: Session, enrollment_id: int, n: int) -> None:
    n = max(1, min(5, n))
    plan = InstallmentPlan(enrollment_id=enrollment_id, total_installments=n, status="active")
    db.add(plan)
    db.flush()
    today = datetime.utcnow().date()
    for i in range(1, n + 1):
        due = today + timedelta(days=30 * (i - 1))
        db.add(
            InstallmentPayment(
                installment_plan_id=plan.id,
                installment_no=i,
                amount=0,
                due_date=due,
                status="pending",
            )
        )


def record_activity(db: Session, student: Student, activity_type: str, ref_id: int | None = None) -> None:
    if student.hkid:
        db.add(ActivityLog(member_hkid=student.hkid, type=activity_type, ref_id=ref_id))


def _migrate_courses_extended_columns(db: Session) -> None:
    stmts = [
        "ALTER TABLE zomate_fs_courses ADD COLUMN IF NOT EXISTS total_lessons INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE zomate_fs_courses ADD COLUMN IF NOT EXISTS lesson_weekdays VARCHAR(32) NOT NULL DEFAULT '0'",
        "ALTER TABLE zomate_fs_courses ADD COLUMN IF NOT EXISTS series_start_date DATE NULL",
        "ALTER TABLE zomate_fs_courses ADD COLUMN IF NOT EXISTS series_end_date DATE NULL",
    ]
    try:
        for s in stmts:
            db.execute(text(s))
        db.commit()
    except Exception:
        db.rollback()


def _migrate_branch_extended_columns(db: Session) -> None:
    stmts = [
        "ALTER TABLE zomate_fs_branches ADD COLUMN IF NOT EXISTS business_start_time VARCHAR(5) NOT NULL DEFAULT '09:00'",
        "ALTER TABLE zomate_fs_branches ADD COLUMN IF NOT EXISTS business_end_time VARCHAR(5) NOT NULL DEFAULT '22:00'",
        "ALTER TABLE zomate_fs_branches ADD COLUMN IF NOT EXISTS remarks TEXT NULL",
        "ALTER TABLE zomate_fs_branches ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE",
    ]
    try:
        for s in stmts:
            db.execute(text(s))
        db.commit()
    except Exception:
        db.rollback()


def _migrate_management_columns(db: Session) -> None:
    stmts = [
        "ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS hkid VARCHAR(32) NULL",
        "ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS date_of_birth DATE NULL",
        "ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS used_mobile_number VARCHAR(30) NULL",
        "ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS emergency_contact_name VARCHAR(120) NULL",
        "ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS emergency_contact_phone VARCHAR(30) NULL",
        "ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS photo_path VARCHAR(512) NULL",
        "ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS signature_image_url VARCHAR(512) NULL",
        "ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS signature_image_blob BYTEA NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_zomate_fs_students_hkid ON zomate_fs_students (hkid)",
        "ALTER TABLE zomate_fs_coaches ADD COLUMN IF NOT EXISTS specialty VARCHAR(160) NULL",
        "ALTER TABLE zomate_fs_coaches ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE",
        "ALTER TABLE zomate_fs_renewal_records ADD COLUMN IF NOT EXISTS package_id INTEGER NULL REFERENCES zomate_fs_packages(id)",
        "ALTER TABLE zomate_fs_renewal_records ADD COLUMN IF NOT EXISTS coach_id INTEGER NULL REFERENCES zomate_fs_coaches(id)",
        "ALTER TABLE zomate_fs_renewal_records ADD COLUMN IF NOT EXISTS branch_id INTEGER NULL REFERENCES zomate_fs_branches(id)",
        "ALTER TABLE zomate_fs_renewal_records ADD COLUMN IF NOT EXISTS amount NUMERIC(12,2) NULL",
        "ALTER TABLE zomate_fs_renewal_records ADD COLUMN IF NOT EXISTS receipt_id INTEGER NULL REFERENCES zomate_fs_receipts(id)",
        "CREATE INDEX IF NOT EXISTS ix_zomate_fs_receipts_member_hkid ON zomate_fs_receipts (member_hkid)",
        "CREATE INDEX IF NOT EXISTS ix_zomate_fs_expenses_date ON zomate_fs_expenses (date)",
        "CREATE INDEX IF NOT EXISTS ix_zomate_fs_activity_log_member_hkid ON zomate_fs_activity_log (member_hkid)",
        "CREATE INDEX IF NOT EXISTS ix_zomate_fs_activity_log_created_at ON zomate_fs_activity_log (created_at)",
    ]
    try:
        for s in stmts:
            db.execute(text(s))
        db.commit()
    except Exception:
        db.rollback()


def _migrate_coach_hire_date(db: Session) -> None:
    """教練入職日期：新欄位，並以 created_at 日期回填既有資料。"""
    try:
        db.execute(text("ALTER TABLE zomate_fs_coaches ADD COLUMN IF NOT EXISTS hire_date DATE NULL"))
        db.commit()
    except Exception:
        db.rollback()
    try:
        db.execute(text("UPDATE zomate_fs_coaches SET hire_date = CAST(created_at AS date) WHERE hire_date IS NULL"))
        db.commit()
    except Exception:
        db.rollback()


def _seed_default_branches(db: Session) -> None:
    branches = [
        {
            "code": "TST",
            "name": "尖沙咀分店",
            "address": "柯士甸道102號22樓",
            "business_start_time": "09:00",
            "business_end_time": "22:00",
            "remarks": "近佐敦地鐵站D出口",
        },
        {
            "code": "SHEUNGWAN",
            "name": "上環分店",
            "address": "宏基商業大廈一樓全層",
            "business_start_time": "09:00",
            "business_end_time": "22:00",
            "remarks": "上環街市及文娛中心對面",
        },
    ]
    for item in branches:
        row = db.query(Branch).filter(Branch.code == item["code"]).first()
        if row is None:
            db.add(Branch(**item))
            continue
        row.name = item["name"]
        row.address = item["address"]
        row.business_start_time = item["business_start_time"]
        row.business_end_time = item["business_end_time"]
        row.remarks = item["remarks"]
        row.active = True


def _seed_management_defaults(db: Session) -> None:
    packages = [
        {"name": "10 堂套票", "sessions": 10, "price": 0},
        {"name": "30 堂套票", "sessions": 30, "price": 0},
    ]
    for item in packages:
        row = db.query(Package).filter(Package.name == item["name"]).first()
        if row is None:
            db.add(Package(**item))
        else:
            row.sessions = item["sessions"]
            row.price = item["price"]
            row.active = True

    for category_name in [
        "新學生一對一",
        "新學生一對二",
        "續會學生一對一",
        "續會學生一對二",
        "自帶學生一對一",
        "自帶學生一對二",
        "Yoga 瑜珈",
        "Stretching 拉伸",
        "Pilates 普拉提",
    ]:
        category = db.query(CourseCategory).filter(CourseCategory.name == category_name).first()
        if category is None:
            db.add(CourseCategory(name=category_name, is_active=True, is_deleted=False, created_by_role="seed"))
        else:
            category.is_active = True
            category.is_deleted = False

    first_branch = db.query(Branch).order_by(Branch.id).first()
    if first_branch and db.query(Coach).count() == 0:
        db.add(
            Coach(
                full_name="Zomate Coach",
                phone="00000000",
                branch_id=first_branch.id,
                specialty="General",
                active=True,
                hire_date=date.today(),
            )
        )
    if first_branch and not db.query(Coach).filter(Coach.phone == "90000001").first():
        db.add(
            Coach(
                full_name="Coach Demo",
                phone="90000001",
                branch_id=first_branch.id,
                specialty="Demo",
                active=True,
                hire_date=date.today(),
            )
        )

    tst_branch = db.query(Branch).filter(Branch.code == "TST").first() or first_branch
    if tst_branch and not db.query(Coach).filter(Coach.phone == "90008888").first():
        db.add(
            Coach(
                full_name="Fung Lo",
                phone="90008888",
                branch_id=tst_branch.id,
                specialty=None,
                active=True,
                hire_date=date.today(),
            )
        )


def parse_lesson_weekdays_str(raw: str | None) -> list[int]:
    if not raw or not str(raw).strip():
        return [0]
    out: list[int] = []
    for part in str(raw).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            v = int(part)
        except ValueError:
            continue
        if 0 <= v <= 6:
            out.append(v)
    return sorted(set(out)) if out else [0]


def enumerate_lesson_dates(start: date, weekdays: list[int], count: int) -> list[date]:
    """[F009][S001]
    Feature: Scheduled course & enrollment PINs
    Step: Expand ``count`` lesson calendar dates from ``start`` honoring weekday set
    Logic: Scan window scales with ``count`` so e.g. 120 weekly lessons are not truncated by a fixed 800-day cap.
    """
    if count < 1:
        return []
    wd_set = set(w for w in weekdays if 0 <= w <= 6)
    if not wd_set:
        wd_set = {start.weekday()}
    dates: list[date] = []
    d = start
    # Need enough iterations for ``count`` matches when weekdays are sparse (e.g. 120 Mondays ≈ 840 days).
    max_days = max(800, count * 14 + 60)
    guard = 0
    while len(dates) < count and guard < max_days:
        if d.weekday() in wd_set:
            dates.append(d)
            if len(dates) >= count:
                break
        d += timedelta(days=1)
        guard += 1
    return dates


def get_lesson_dates_for_course(course: Course) -> list[date]:
    """[F009][S002]
    Feature: Scheduled course & enrollment PINs
    Step: Expand series dates for ``resolve_checkin_pin_context`` / today-lesson picker
    Logic: Align with CourseCreate.total_lessons upper bound (currently 30 for scheduled packages).
    """
    ws = parse_lesson_weekdays_str(course.lesson_weekdays)
    start = course.series_start_date or course.scheduled_start.date()
    try:
        n = int(course.total_lessons)
    except (TypeError, ValueError):
        n = 1
    # Align with CourseCreate.total_lessons upper bound (scheduled packages).
    n = max(1, min(30, n))
    if n <= 1 and (not getattr(course, "lesson_weekdays", None) or course.lesson_weekdays == "0"):
        return [course.scheduled_start.date()]
    return enumerate_lesson_dates(start, ws, n)


def course_active_at_now(course: Course, now: datetime) -> bool:
    if now.tzinfo is None:
        now_local = now.replace(tzinfo=HK)
    else:
        now_local = now.astimezone(HK)
    d = now_local.date()
    if d not in get_lesson_dates_for_course(course):
        return False
    t_start = course.scheduled_start.time()
    t_end = course.scheduled_end.time()
    t = now_local.time()
    if t_start <= t_end:
        return t_start <= t <= t_end
    return t >= t_start or t <= t_end


def resolve_today_primary_course_for_student(
    db: Session, student: Student, now: datetime | None = None
) -> tuple[Course | None, Coach | None]:
    """Pick one class today when using account PIN / FaceID (not class PIN)."""
    now = now or now_hk()
    rows = (
        db.query(Course, Coach)
        .join(CourseEnrollment, CourseEnrollment.course_id == Course.id)
        .join(Coach, Coach.id == Course.coach_id)
        .filter(
            CourseEnrollment.student_id == student.id,
            ~Course.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "courses")),
            ~Coach.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "coaches")),
        )
        .all()
    )
    candidates: list[tuple[Course, Coach]] = []
    for course, coach in rows:
        if course_active_at_now(course, now):
            candidates.append((course, coach))
    if not candidates:
        return None, None
    if len(candidates) == 1:
        return candidates[0][0], candidates[0][1]
    for course, coach in candidates:
        if course.scheduled_start <= now <= course.scheduled_end:
            return course, coach
    best = min(candidates, key=lambda r: abs((r[0].scheduled_start - now).total_seconds()))
    return best[0], best[1]


def resolve_checkin_pin_context(
    db: Session, student: Student, pin: str
) -> tuple[CourseEnrollment, Course, Coach, str] | Literal["blocked_installment_unpaid"] | None:
    """Class PIN → that course when paid segment allows check-in & today is a lesson day."""
    pin = pin.strip()
    now = now_hk()
    enrs = (
        db.query(CourseEnrollment)
        .options(
            joinedload(CourseEnrollment.course).joinedload(Course.coach),
        )
        .filter(CourseEnrollment.student_id == student.id)
        .filter(~CourseEnrollment.course_id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "courses")))
        .order_by(CourseEnrollment.id.asc())
        .all()
    )
    for enr in enrs:
        if not _enrollment_matches_class_pin(enr, pin):
            continue
        if not _segment_paid_for_matched_pin(enr, pin):
            return "blocked_installment_unpaid"
        c = enr.course
        if now.date() in get_lesson_dates_for_course(c):
            return enr, c, c.coach, "class_pin"
        return None
    return None


def course_to_out(course: Course) -> CourseOut:
    branch = course.branch
    coach = course.coach
    enrollments: list[CourseEnrollmentOut] = []
    for e in course.enrollments:
        st = e.student
        segs = _parse_segment_pins_json(getattr(e, "segment_pins_json", None))
        enrollments.append(
            CourseEnrollmentOut(
                student_id=st.id,
                student_name=st.full_name,
                student_phone=st.phone,
                checkin_pin=e.checkin_pin,
                installment_segments=segs,
            )
        )
    ws = parse_lesson_weekdays_str(getattr(course, "lesson_weekdays", None))
    total = getattr(course, "total_lessons", None) or 1
    s_start = getattr(course, "series_start_date", None)
    s_end = getattr(course, "series_end_date", None)
    return CourseOut(
        id=course.id,
        title=course.title,
        branch_id=course.branch_id,
        branch_name=branch.name,
        branch_address=branch.address,
        coach_id=course.coach_id,
        coach_name=coach.full_name,
        scheduled_start=course.scheduled_start,
        scheduled_end=course.scheduled_end,
        created_at=course.created_at,
        total_lessons=int(total),
        lesson_weekdays=ws,
        series_start_date=s_start,
        series_end_date=s_end,
        enrollments=enrollments,
    )


def _lesson_balance_sum(db: Session, student_id: int) -> int:
    """[F007][S002]
    Feature: Lesson ledger (Phase-1)
    Step: Balance query
    Logic: 學員剩餘堂數 = ``SUM(zomate_fs_lesson_ledger.delta_lessons)``；唔再讀 ``students.lesson_balance`` 欄位。
    """
    total = db.scalar(
        select(func.coalesce(func.sum(LessonLedgerEntry.delta_lessons), 0)).where(
            LessonLedgerEntry.student_id == student_id,
        ),
    )
    return int(total or 0)


def apply_lesson_ledger_delta(
    db: Session,
    student: Student,
    delta_lessons: int,
    reason: str,
    *,
    enrollment_id: int | None = None,
    created_by_role: str = "system",
) -> int:
    """[F007][S002]
    Feature: Lesson ledger (Phase-1)
    Step: Credit / debit posting
    Logic: 寫入一筆 ledger 後；回傳該學員 SUM(ledger)（冇 denormalized 欄位）。
    """
    if delta_lessons == 0:
        return _lesson_balance_sum(db, student.id)
    db.add(
        LessonLedgerEntry(
            student_id=student.id,
            enrollment_id=enrollment_id,
            delta_lessons=delta_lessons,
            reason=reason,
            created_by_role=created_by_role,
        )
    )
    db.flush()
    return _lesson_balance_sum(db, student.id)


async def perform_lesson_checkin(
    db: Session,
    student: Student,
    channel: str,
    remarks: str | None = None,
    *,
    resolved_course_enrollment: CourseEnrollment | None = None,
    resolved_course: Course | None = None,
    notified_coach: Coach | None = None,
    pin_resolution: str = "unknown",
) -> dict:
    if _lesson_balance_sum(db, student.id) <= 0:
        raise HTTPException(status_code=400, detail="Student has no remaining lessons.")

    attended_at = datetime.utcnow()
    session_day = hk_calendar_date(attended_at)

    if resolved_course:
        dup = (
            db.query(Attendance)
            .filter(
                Attendance.student_id == student.id,
                Attendance.course_id == resolved_course.id,
                Attendance.session_calendar_date == session_day,
            )
            .first()
        )
        if dup:
            raise HTTPException(status_code=409, detail="Already checked in for this session today.")

    # TODO [F003][S006] True course-enrollment redeem:
    # `zomate_fs_lesson_ledger.enrollment_id` and `zomate_fs_attendance.enrollment_id`
    # currently point to `zomate_fs_category_enrollments`, not `zomate_fs_course_enrollments`.
    # Add `course_enrollment_id` nullable FKs in a migration, then persist
    # `resolved_course_enrollment.id` here for exact course package traceability.
    bal_after = apply_lesson_ledger_delta(db, student, -1, "checkin_redeem", created_by_role="student")
    checkin_log = CheckinLog(student_id=student.id, channel=channel, remarks=remarks)
    db.add(checkin_log)
    db.flush()

    if resolved_course:
        db.add(
            Attendance(
                student_id=student.id,
                enrollment_id=None,
                coach_id=resolved_course.coach_id,
                branch_id=resolved_course.branch_id,
                course_id=resolved_course.id,
                attended_at=attended_at,
                session_calendar_date=session_day,
            )
        )

    log_whatsapp(
        db,
        student,
        student.phone,
        f"上堂通知：{student.full_name} 已簽到，剩餘堂數 {bal_after}。",
    )
    # TODO [F005][S003] WhatsApp reminder hook:
    # Replace this local log with provider/webhook delivery after check-in redeem.
    # Payload should include student name, phone, course title, course_enrollment_id,
    # installment PIN segment, balance after redeem, and low-balance reminder threshold.
    coach_msg = f"教練通知：學生 {student.full_name} 已簽到。"
    if notified_coach:
        log_whatsapp(db, student, notified_coach.phone, coach_msg)
    else:
        log_whatsapp(db, student, "coach-demo", coach_msg)

    detail_obj: dict = {
        "channel": channel,
        "pin_resolution": pin_resolution,
        "lesson_balance_after": bal_after,
        "checkin_id": checkin_log.id,
        "course_title": resolved_course.title if resolved_course else None,
        "course_enrollment_id": resolved_course_enrollment.id if resolved_course_enrollment else None,
        "notified_coach_phone": notified_coach.phone if notified_coach else None,
    }
    db.add(
        AuditLog(
            action="checkin_redeem",
            student_id=student.id,
            course_id=resolved_course.id if resolved_course else None,
            coach_id=notified_coach.id if notified_coach else None,
            detail=json.dumps(detail_obj, ensure_ascii=False),
        )
    )

    db.commit()
    db.refresh(student)
    db.refresh(checkin_log)

    event_payload = {
        "event": "checkin_acknowledged",
        "checkin_id": checkin_log.id,
        "student_id": student.id,
        "student_name": student.full_name,
        "student_phone": student.phone,
        "lesson_balance": bal_after,
        # Coach calendar UX：前台用 course_id／session_calendar_date 標記「已簽到扣堂」之課程格。
        "course_id": resolved_course.id if resolved_course else None,
        "session_calendar_date": session_day.isoformat() if resolved_course else None,
        "course_title": resolved_course.title if resolved_course else None,
    }
    await manager.broadcast_json(event_payload)

    return {
        "message": "Check-in success",
        "student": {
            "id": student.id,
            "full_name": student.full_name,
            "phone": student.phone,
            "lesson_balance": bal_after,
            "channel": channel,
        },
        "notified_coach": (
            {"id": notified_coach.id, "full_name": notified_coach.full_name, "phone": notified_coach.phone}
            if notified_coach
            else None
        ),
        "resolved_course_id": resolved_course.id if resolved_course else None,
    }


def _sync_startup() -> None:
    Base.metadata.create_all(bind=engine)
    db = next(get_db())
    try:
        _migrate_branch_extended_columns(db)
        _migrate_courses_extended_columns(db)
        _migrate_management_columns(db)
        _migrate_coach_hire_date(db)
        _seed_default_branches(db)
        _seed_management_defaults(db)
        _seed_default_users(db)
        db.commit()
    finally:
        db.close()


@app.on_event("startup")
async def _startup_keepalive_and_db() -> None:
    configure_logging(settings.log_level)
    log_event("startup_begin")
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _sync_startup)
    if os.environ.get("AGENT_DEBUG", "").lower() in ("1", "true", "yes"):
        paths = [getattr(r, "path", "") for r in app.routes if getattr(r, "path", None)]
        _agent_dbg(
            "H4",
            "main.py:startup",
            "renewal_route_probe",
            {"renewal_in_routes": "/api/renewal" in paths, "nroutes": len(paths)},
        )
    if settings.keepalive_enabled and (settings.public_base_url or "").strip():
        stop = asyncio.Event()
        app.state._keepalive_stop = stop
        app.state._keepalive_task = asyncio.create_task(keepalive_loop(settings, stop))
        log_event("keepalive_task_scheduled")


@app.on_event("shutdown")
async def _shutdown_keepalive() -> None:
    task = getattr(app.state, "_keepalive_task", None)
    stop = getattr(app.state, "_keepalive_stop", None)
    if task and stop:
        stop.set()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


API_SERVICE_NAME = "zomate-fitness-api"


def _health_liveness_payload() -> dict:
    return liveness_payload(instance_id())


def _health_database_payload(db: Session) -> dict:
    db.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "database": "connected",
        "service": API_SERVICE_NAME,
        "instance_id": instance_id(),
    }


# [F007][S004]
# Feature: Backend platform (FastAPI & PostgreSQL)
# Step: Ops & observability — health and readiness probes
# Logic: Liveness without PostgreSQL; readiness runs SELECT 1 on DATABASE_URL (Swagger tags=health).
# -----------------------------------------------------------------------------


@app.get("/health", tags=["health"], summary="Liveness（程序運行）")
def health() -> dict:
    """Kubernetes / Render **liveness**：不依賴資料庫。"""
    return _health_liveness_payload()


@app.get("/health/db", tags=["health"], summary="Readiness · PostgreSQL")
def health_db(db: Session = Depends(get_db)) -> dict:
    """**Readiness**：``SELECT 1`` on ``DATABASE_URL``（eventxp / Render PostgreSQL）。"""
    return _health_database_payload(db)


@app.get("/api/health", tags=["health"], summary="Liveness（/api 前缀）")
def api_health() -> dict:
    """與 ``GET /health`` 相同，方便前端與統一路径前缀。"""
    return _health_liveness_payload()


@app.get("/api/health/db", tags=["health"], summary="Readiness · PostgreSQL（/api 前缀）")
def api_health_db(db: Session = Depends(get_db)) -> dict:
    """與 ``GET /health/db`` 相同。"""
    return _health_database_payload(db)


# [F003][S001]
# Feature: Attendance & Today-Only QR Check-in
# Step: QR scan / paste — public kiosk search after scanning QR
# Logic: Name or phone fragment lookup returning id and balance before PIN verification.


@app.get("/api/public/student-search")
def public_student_search(q: str = "", db: Session = Depends(get_db)) -> list[dict]:
    """Kiosk-friendly search after QR scan (name or phone fragment).

    Matches **full_name** with collapsed whitespace so ``Larry Lo`` finds ``Larry  Lo``.
    """
    raw = " ".join((q or "").split()).strip()
    if len(raw) < 1:
        return []
    if len(raw) > 64:
        raise HTTPException(status_code=400, detail="Query too long")

    escaped = raw.replace("\\", "").replace("%", "").replace("_", "").strip()
    if not escaped:
        return []

    deleted_ids = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")

    normalized_name = func.regexp_replace(func.trim(Student.full_name), "[[:space:]]+", " ", "g")
    pattern = f"%{escaped}%"

    rows = (
        db.query(Student)
        .filter(~Student.id.in_(deleted_ids))
        .filter(
            or_(
                normalized_name.ilike(pattern),
                Student.phone.ilike(pattern),
            )
        )
        .order_by(Student.full_name.asc())
        .limit(25)
        .all()
    )
    return [
        {
            "id": s.id,
            "full_name": s.full_name,
            "phone": s.phone,
            "lesson_balance": _lesson_balance_sum(db, s.id),
        }
        for s in rows
    ]


# [F003][S001]
# Feature: Attendance & Today-Only QR Check-in
# Step: Today's lessons for enrolled student (Hong Kong calendar day)
# Logic: Courses where today ∈ lesson dates; omit checkin_pin from public JSON.


@app.get("/api/public/student-today-lessons")
def public_student_today_lessons(
    student_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
) -> list[dict]:
    student = db.query(Student).filter(Student.id == student_id).first()
    if student is None or _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Student not found.")
    today = now_hk().date()
    rows = (
        db.query(Course, Coach)
        .join(CourseEnrollment, CourseEnrollment.course_id == Course.id)
        .join(Coach, Coach.id == Course.coach_id)
        .filter(
            CourseEnrollment.student_id == student_id,
            ~Course.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "courses")),
            ~Coach.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "coaches")),
        )
        .all()
    )
    out: list[dict] = []
    for course, coach in rows:
        if today not in get_lesson_dates_for_course(course):
            continue
        out.append(
            {
                "course_id": course.id,
                "title": course.title or "Course",
                "coach_name": coach.full_name,
                "scheduled_start": course.scheduled_start.isoformat(),
                "scheduled_end": course.scheduled_end.isoformat(),
            }
        )
    out.sort(key=lambda x: x["scheduled_start"])
    return out


# [F003][S001]
# Feature: Attendance & Today-Only QR Check-in
# Step: Realtime check-in broadcast channel
# Logic: WebSocket endpoint for coach calendar and kiosk monitors (manager hub).


@app.websocket("/ws/checkins")
async def websocket_checkins(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        await websocket.send_text(
            json.dumps({"event": "connected", "message": "Realtime check-in stream connected"})
        )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# [F001][S001]
# Feature: Student Onboarding
# Step: Entry form and registration HTTP (legacy / wizard payloads)
# Logic: Persist Student rows, PAR-Q paths, WhatsApp welcome hooks.


@app.post("/api/onboarding", response_model=StudentOut)
def onboarding(payload: StudentOnboardCreate, db: Session = Depends(get_db)) -> StudentOut:
    existing = db.query(Student).filter(Student.phone == payload.phone).first()
    if existing:
        raise HTTPException(status_code=409, detail="Phone already exists.")

    data = payload.model_dump()
    student = Student(**data)
    db.add(student)
    db.commit()
    db.refresh(student)
    return student_to_student_out(db, student)


@app.post("/api/v1/students/register")
def register_student_v1(payload: StudentRegisterV1, db: Session = Depends(get_db)) -> dict:
    """F01 multi-step wizard — persist to PostgreSQL + return PIN + membership expiry.

    QR / kiosk **registration with SMS OTP** uses ``POST /api/register/*`` instead; keep this route for staff-assisted onboarding.
    """
    phone_raw = normalize_hk_phone_local_eight(payload.phone.strip())
    if not phone_raw:
        raise HTTPException(
            status_code=400,
            detail="電話須為香港 8 位手機號碼（請填 +852xxxxxxxx 或只填八位數字）。",
        )
    phone_vars = _hk_phone_lookup_variants(phone_raw)

    hkid = normalize_hkid(payload.hkid)
    eco_raw = normalize_hk_phone_local_eight(payload.emergency_contact_phone.strip())
    if not eco_raw:
        raise HTTPException(
            status_code=400,
            detail="緊急聯絡電話須為香港 8 位手機號碼。",
        )
    emergency_contact_phone = eco_raw

    deleted_ids_sq = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")

    existing = (
        db.query(Student).filter(~Student.id.in_(deleted_ids_sq)).filter(Student.phone.in_(phone_vars)).first()
    )
    if hkid and (
        db.query(Student)
        .filter(
            Student.hkid == hkid,
            ~Student.phone.in_(phone_vars),
            ~Student.id.in_(deleted_ids_sq),
        )
        .first()
    ):
        raise HTTPException(status_code=409, detail="HKID already registered.")
    expiry_iso = _membership_expiry_iso(payload.package_sessions)

    if existing is not None and _is_deleted(db, "students", existing.id):
        raise HTTPException(status_code=409, detail="Student phone belongs to a deleted record.")

    if existing is not None:
        if payload.form_type != "renewal":
            raise HTTPException(
                status_code=409,
                detail="電話已登記。如需續會請選「Renewal 續會」或聯絡中心。",
            )
        merged_notes = (existing.health_notes or "").strip()
        block = _register_v1_health_notes(payload)
        existing.health_notes = (merged_notes + "\n\n--- renewal registration ---\n" + block)[-120_000:]
        existing.full_name = payload.full_name.strip()
        existing.hkid = hkid
        existing.date_of_birth = payload.date_of_birth
        existing.emergency_contact_name = payload.emergency_contact_name.strip()
        existing.emergency_contact_phone = emergency_contact_phone
        if payload.email is not None:
            existing.email = (payload.email.strip() or None)
        existing.disclaimer_accepted = True
        _apply_signature_image(existing, payload.digital_signature)
        apply_lesson_ledger_delta(
            db,
            existing,
            int(payload.package_sessions),
            "register_v1_renewal",
            created_by_role="onboarding",
        )
        db.add(
            AuditLog(
                action="register_student_v1_renewal",
                student_id=existing.id,
                detail=json.dumps({"package_sessions": payload.package_sessions}, ensure_ascii=False),
            )
        )
        log_whatsapp(
            db,
            existing,
            phone_raw,
            f"續會登記已收到：已加 {payload.package_sessions} 堂，現有餘額 {_lesson_balance_sum(db, existing.id)} 堂。",
        )
        db.commit()
        db.refresh(existing)
        return {"membership_expiry_iso": expiry_iso}

    if payload.form_type == "renewal":
        raise HTTPException(
            status_code=404,
            detail="找不到此電話之學籍。請改選「新人申請」或核對號碼。",
        )

    student = Student(
        full_name=payload.full_name.strip(),
        hkid=hkid,
        phone=phone_raw,
        email=(payload.email or "").strip() or None,
        date_of_birth=payload.date_of_birth,
        emergency_contact_name=payload.emergency_contact_name.strip(),
        emergency_contact_phone=emergency_contact_phone,
        health_notes=_register_v1_health_notes(payload),
        disclaimer_accepted=True,
    )
    db.add(student)
    db.flush()
    _apply_signature_image(student, payload.digital_signature)
    apply_lesson_ledger_delta(
        db,
        student,
        int(payload.package_sessions),
        "register_v1_new",
        created_by_role="onboarding",
    )
    db.add(
        AuditLog(
            action="register_student_v1",
            student_id=student.id,
            detail=json.dumps(
                {"hkid": payload.hkid.strip(), "sessions": payload.package_sessions},
                ensure_ascii=False,
            ),
        )
    )
    log_whatsapp(
        db,
        student,
        phone_raw,
        f"歡迎 {student.full_name}！已存入 {payload.package_sessions} 堂。簽到請使用課程專屬 PIN（報名課程後將以 WhatsApp 發送）。",
    )
    db.commit()
    db.refresh(student)
    return {"membership_expiry_iso": expiry_iso}


@app.post("/api/members/duplicate-check")
def member_duplicate_check(payload: MemberProspectDupCheck, db: Session = Depends(get_db)) -> dict:
    """Feature F008:F01 -- 第一步「下一步」前預檢；毋須 Bearer。"""
    deleted_ids_sq = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")
    base = db.query(Student).filter(~Student.id.in_(deleted_ids_sq))
    hkid_n = normalize_hkid(payload.hkid)
    phone_local = normalize_hk_phone_local_eight(payload.phone.strip())
    if not phone_local:
        raise HTTPException(
            status_code=400,
            detail="電話須為香港 8 位手機號碼（預設 +852，只可填數字八位亦可）。",
        )
    variants = _hk_phone_lookup_variants(phone_local)
    dup_hkid = base.filter(Student.hkid == hkid_n).first()
    dup_phone = base.filter(Student.phone.in_(variants)).first()
    if dup_hkid or dup_phone:
        parts: list[str] = []
        if dup_hkid:
            parts.append("此證件號碼（HKID／簡填格式）已被登記")
        if dup_phone:
            parts.append("此電話號碼已被登記")
        message = "；".join(parts) + "。請改用「續會」或聯絡櫃台。"
        return {"blocked": True, "message": message}
    return {"blocked": False, "message": None}


@app.post("/api/members")
def create_member(payload: MemberCreate, db: Session = Depends(get_db)) -> dict:
    hkid = normalize_hkid(payload.hkid)
    phone_raw = normalize_hk_phone_local_eight(payload.phone.strip())
    if not phone_raw:
        raise HTTPException(
            status_code=400,
            detail="電話須為香港 8 位手機號碼（預設 +852）。",
        )
    phone_vars = _hk_phone_lookup_variants(phone_raw)
    eco_raw = normalize_hk_phone_local_eight(payload.emergency_contact_phone.strip())
    if not eco_raw:
        raise HTTPException(
            status_code=400,
            detail="緊急聯絡電話須為香港 8 位手機號碼。",
        )
    deleted_ids_sq = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")
    if db.query(Student).filter(~Student.id.in_(deleted_ids_sq)).filter(Student.hkid == hkid).first():
        raise HTTPException(status_code=409, detail="HKID already registered.")
    if db.query(Student).filter(~Student.id.in_(deleted_ids_sq)).filter(Student.phone.in_(phone_vars)).first():
        raise HTTPException(status_code=409, detail="Phone already registered.")
    notes = "\n".join(
        [
            f"HKID: {hkid}",
            f"Date of birth: {payload.date_of_birth.isoformat()}",
            f"Emergency: {payload.emergency_contact_name.strip()} / {eco_raw}",
            "Digital signature (step 3): canvas image saved",
            f"PAR-Q JSON: {json.dumps(payload.parq.model_dump(), ensure_ascii=False)}",
            f"Medical clearance file: {(payload.medical_clearance_file_name or '').strip()}",
        ]
    )
    student = Student(
        full_name=payload.full_name.strip(),
        hkid=hkid,
        phone=phone_raw,
        email=(payload.email or "").strip() or None,
        date_of_birth=payload.date_of_birth,
        emergency_contact_name=payload.emergency_contact_name.strip(),
        emergency_contact_phone=eco_raw,
        health_notes=notes,
        disclaimer_accepted=True,
    )
    db.add(student)
    db.flush()
    _apply_signature_image(student, payload.digital_signature)
    db.add(AuditLog(action="member_create", student_id=student.id, detail=json.dumps({"hkid": hkid}, ensure_ascii=False)))
    record_activity(db, student, "member_create", student.id)
    db.commit()
    db.refresh(student)
    return {"member": student_to_member_dict(db, student)}


@app.get("/api/members/search")
def search_members(q: str = "", db: Session = Depends(get_db)) -> list[dict]:
    raw = " ".join((q or "").split()).strip()
    if len(raw) < 1:
        return []
    escaped = raw.replace("\\", "").replace("%", "").replace("_", "")
    pattern = f"%{escaped}%"
    deleted_ids = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")
    rows = (
        db.query(Student)
        .filter(~Student.id.in_(deleted_ids))
        .filter(or_(Student.full_name.ilike(pattern), Student.phone.ilike(pattern), Student.hkid.ilike(pattern)))
        .order_by(Student.full_name)
        .limit(20)
        .all()
    )
    return [student_to_member_dict(db, row) for row in rows]


@app.get("/api/members/lookup-phone")
def lookup_member_by_phone(phone: str = Query(..., min_length=3), db: Session = Depends(get_db)) -> dict:
    """續會 Step 1：以電話（預設 +852 八位）查找唯一學員。"""
    local = normalize_hk_phone_local_eight(phone.strip())
    if not local:
        raise HTTPException(
            status_code=400,
            detail="電話須為香港 8 位手機號碼（請填 +852xxxxxxxx 或只填八位數字）。",
        )
    variants = _hk_phone_lookup_variants(local)
    deleted_ids = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")
    st = db.query(Student).filter(~Student.id.in_(deleted_ids), Student.phone.in_(variants)).first()
    if st is None:
        raise HTTPException(status_code=404, detail="找不到此電話的學員。")
    return student_to_member_dict(db, st)


@app.get("/api/members/{hkid}")
def get_member(hkid: str, db: Session = Depends(get_db)) -> dict:
    return student_to_member_dict(db, get_student_by_hkid_or_404(db, hkid))


def _member_full_payload(db: Session, student: Student, *, fallback_hkid: str | None = None) -> dict:
    """[F001][S002] Build student detail payload; route may lookup by id or HKID."""
    receipts = db.query(Receipt).filter(Receipt.student_id == student.id).order_by(Receipt.created_at.desc()).all()
    renewals = db.query(RenewalRecord).filter(RenewalRecord.student_id == student.id).order_by(RenewalRecord.created_at.desc()).all()
    trials = _trial_records_from_audit(db, student.id)
    trial_coach_ids = [t["coach_id"] for t in trials if t.get("coach_id") is not None]
    trial_branch_ids = [t["branch_id"] for t in trials if t.get("branch_id") is not None]
    trial_coaches = {c.id: c.full_name for c in db.query(Coach).filter(Coach.id.in_(trial_coach_ids)).all()} if trial_coach_ids else {}
    trial_branches = {b.id: b.name for b in db.query(Branch).filter(Branch.id.in_(trial_branch_ids)).all()} if trial_branch_ids else {}
    activity_hkid = student.hkid or (normalize_hkid(fallback_hkid) if fallback_hkid else None)
    logs = (
        db.query(ActivityLog)
        .filter(ActivityLog.member_hkid == activity_hkid)
        .order_by(ActivityLog.created_at.desc())
        .limit(100)
        .all()
        if activity_hkid
        else []
    )
    return {
        "profile": student_to_member_dict(db, student),
        "receipts": [
            {
                "id": r.id,
                "file_path": r.file_path,
                "file_url": _file_url(r.file_path),
                "amount": float(r.amount) if r.amount is not None else None,
                "payment_method": r.payment_method,
                "note": r.note,
                "source": r.source,
                "created_at": r.created_at.isoformat(),
            }
            for r in receipts
        ],
        "packages": [
            {
                "id": rr.id,
                "package_id": rr.package_id,
                "coach_id": rr.coach_id,
                "branch_id": rr.branch_id,
                "name": f"{rr.lessons} 堂",
                "lessons": rr.lessons,
                "coach": rr.coach_name,
                "payment_method": rr.payment_method,
                "amount": float(rr.amount) if rr.amount is not None else None,
                "renewal_date": rr.renewal_date.isoformat(),
                "created_at": rr.created_at.isoformat(),
            }
            for rr in renewals
        ],
        "trial_classes": [
            {
                "id": t["id"],
                "type": t["type"],
                "coach_id": t.get("coach_id"),
                "coach_name": t.get("coach_name") or (trial_coaches.get(t["coach_id"]) if t.get("coach_id") is not None else None),
                "branch_id": t.get("branch_id"),
                "branch_name": t.get("branch_name") or (trial_branches.get(t["branch_id"]) if t.get("branch_id") is not None else None),
                "course_category_id": t.get("course_category_id"),
                "course_category_name": t.get("course_category_name"),
                "trial_kind_id": t.get("trial_kind_id"),
                "trial_kind_label_zh": t.get("trial_kind_label_zh"),
                "class_date": t.get("class_date"),
                "note": t.get("note"),
                "created_at": t["created_at"],
            }
            for t in trials
        ],
        "activity_log": [
            {
                "id": a.id,
                "type": a.type,
                "ref_id": a.ref_id,
                "created_at": a.created_at.isoformat(),
            }
            for a in logs
        ],
        "course_checkin_pins": _course_checkin_pins_for_student(db, student),
        "category_enrollments": [
            {
                "id": ce.id,
                "course_category_id": ce.course_category_id,
                "category_name": ce.course_category.name,
                "status": ce.status,
                "total_lessons": ce.total_lessons,
                "started_at": ce.started_at.isoformat(),
                "installment_plans": [
                    {
                        "id": plan.id,
                        "total_installments": plan.total_installments,
                        "status": plan.status,
                        "created_at": plan.created_at.isoformat(),
                        "payments": [
                            {
                                "id": pay.id,
                                "installment_no": pay.installment_no,
                                "amount": float(pay.amount),
                                "due_date": pay.due_date.isoformat(),
                                "paid_at": pay.paid_at.isoformat() if pay.paid_at else None,
                                "status": pay.status,
                            }
                            for pay in sorted(plan.payments, key=lambda p: p.installment_no)
                        ],
                    }
                    for plan in ce.installment_plans
                ],
            }
            for ce in (
                db.query(CategoryEnrollment)
                .options(
                    joinedload(CategoryEnrollment.course_category),
                    joinedload(CategoryEnrollment.installment_plans).joinedload(InstallmentPlan.payments),
                )
                .filter(CategoryEnrollment.student_id == student.id)
                .all()
            )
        ],
    }


@app.get("/api/members/by-id/{student_id}/full")
def get_member_full_by_id(student_id: int, db: Session = Depends(get_db)) -> dict:
    student = db.get(Student, student_id)
    if student is None or _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Student not found.")
    return _member_full_payload(db, student)


@app.patch("/api/members/by-id/{student_id}")
def update_member_by_id(
    student_id: int,
    payload: MemberUpdate,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    """[F001][S003] Staff profile edit; mobile changes retain previous number for traceability."""
    student = db.get(Student, student_id)
    if student is None or _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Student not found.")
    if payload.full_name is not None:
        student.full_name = payload.full_name.strip()
    if payload.email is not None:
        student.email = payload.email.strip() or None
    if payload.date_of_birth is not None:
        student.date_of_birth = payload.date_of_birth
    if payload.emergency_contact_name is not None:
        student.emergency_contact_name = payload.emergency_contact_name.strip() or None
    if payload.emergency_contact_phone is not None:
        raw_emergency = payload.emergency_contact_phone.strip()
        if raw_emergency:
            emergency_phone = normalize_hk_phone_local_eight(raw_emergency)
            if not emergency_phone:
                raise HTTPException(status_code=400, detail="緊急聯絡電話須為香港 8 位手機號碼。")
            student.emergency_contact_phone = emergency_phone
        else:
            student.emergency_contact_phone = None
    if payload.phone is not None:
        phone_raw = normalize_hk_phone_local_eight(payload.phone.strip())
        if not phone_raw:
            raise HTTPException(status_code=400, detail="電話須為香港 8 位手機號碼。")
        if phone_raw != student.phone:
            variants = _hk_phone_lookup_variants(phone_raw)
            active_ids_sq = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")
            other = (
                db.query(Student)
                .filter(~Student.id.in_(active_ids_sq), Student.id != student.id, Student.phone.in_(variants))
                .first()
            )
            if other:
                raise HTTPException(status_code=409, detail="Phone already registered.")
            previous = student.phone
            if student.used_mobile_number:
                used = [x.strip() for x in student.used_mobile_number.split(",") if x.strip()]
                if previous not in used:
                    used.append(previous)
                student.used_mobile_number = ",".join(used)[-30:]
            else:
                student.used_mobile_number = previous
            student.phone = phone_raw
    db.add(
        AuditLog(
            action="member_profile_update",
            student_id=student.id,
            detail=json.dumps({"updated_by": user.username}, ensure_ascii=False),
        )
    )
    record_activity(db, student, "member_profile_update", student.id)
    db.commit()
    db.refresh(student)
    return {"member": student_to_member_dict(db, student)}


@app.get("/api/members/{hkid}/full")
def get_member_full(hkid: str, db: Session = Depends(get_db)) -> dict:
    student = get_student_by_hkid_or_404(db, hkid)
    return _member_full_payload(db, student, fallback_hkid=hkid)


@app.post("/api/members/{hkid}/photo")
def upload_member_photo(hkid: str, file: UploadFile = File(...), db: Session = Depends(get_db)) -> dict:
    student = get_student_by_hkid_or_404(db, hkid)
    path = _save_upload_file(file, "photos", student.hkid or hkid, 2 * 1024 * 1024)
    student.photo_path = path
    photo = StudentPhoto(student_id=student.id, member_hkid=student.hkid or normalize_hkid(hkid), file_path=path)
    db.add(photo)
    db.add(AuditLog(action="member_photo_upload", student_id=student.id, detail=path))
    record_activity(db, student, "member_photo_upload", photo.id)
    db.commit()
    return {"id": photo.id, "file_path": path, "file_url": _file_url(path)}


@app.post("/api/members/{hkid}/receipts")
def upload_member_receipt(
    hkid: str,
    file: UploadFile = File(...),
    amount: float | None = Form(default=None),
    payment_method: str | None = Form(default=None),
    note: str | None = Form(default=None),
    context: str | None = Form(default=None),
    source: str = Form(default="REGISTER"),
    db: Session = Depends(get_db),
) -> dict:
    student = get_student_by_hkid_or_404(db, hkid)
    path = _save_upload_file(file, "receipts", student.hkid or hkid, 5 * 1024 * 1024)
    note_text = (note or "").strip()
    context_text = (context or "").strip()
    if context_text:
        note_text = f"[{context_text}] {note_text}".strip()
    receipt = Receipt(
        student_id=student.id,
        member_hkid=student.hkid or normalize_hkid(hkid),
        file_path=path,
        amount=amount,
        payment_method=(payment_method or "").strip() or None,
        note=note_text or None,
        source=source if source in {"REGISTER", "RENEWAL"} else "REGISTER",
    )
    db.add(receipt)
    db.flush()
    db.add(AuditLog(action="receipt_upload", student_id=student.id, detail=json.dumps({"receipt_id": receipt.id, "source": receipt.source}, ensure_ascii=False)))
    record_activity(db, student, "receipt_upload", receipt.id)
    db.commit()
    return {"id": receipt.id, "file_path": path, "file_url": _file_url(path)}


@app.post("/api/members/by-id/{student_id}/receipts")
def upload_member_receipt_by_id(
    student_id: int,
    file: UploadFile = File(...),
    amount: float | None = Form(default=None),
    payment_method: str | None = Form(default=None),
    note: str | None = Form(default=None),
    context: str | None = Form(default=None),
    source: str = Form(default="RENEWAL"),
    db: Session = Depends(get_db),
) -> dict:
    """[F004][S002] Admin / clerk receipt upload from ID-based student detail route."""
    student = db.get(Student, student_id)
    if student is None or _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Student not found.")
    key = student.hkid or f"student-{student.id}"
    path = _save_upload_file(file, "receipts", key, 5 * 1024 * 1024)
    note_text = (note or "").strip()
    context_text = (context or "").strip()
    if context_text:
        note_text = f"[{context_text}] {note_text}".strip()
    receipt = Receipt(
        student_id=student.id,
        member_hkid=student.hkid or f"ID{student.id}",
        file_path=path,
        amount=amount,
        payment_method=(payment_method or "").strip() or None,
        note=note_text or None,
        source=source if source in {"REGISTER", "RENEWAL"} else "RENEWAL",
    )
    db.add(receipt)
    db.flush()
    db.add(
        AuditLog(
            action="receipt_upload",
            student_id=student.id,
            detail=json.dumps({"receipt_id": receipt.id, "source": receipt.source}, ensure_ascii=False),
        )
    )
    record_activity(db, student, "receipt_upload", receipt.id)
    db.commit()
    return {"id": receipt.id, "file_path": path, "file_url": _file_url(path)}


@app.post("/api/members/{hkid}/resend-pin")
def resend_member_pin(hkid: str, db: Session = Depends(get_db)) -> dict:
    get_student_by_hkid_or_404(db, hkid)
    raise HTTPException(status_code=501, detail="WhatsApp 未接駁 — Coming soon")


@app.post("/api/renewals")
def create_renewal_multipart(
    student_id: int | None = Form(default=None),
    member_hkid: str | None = Form(default=None),
    student_phone: str | None = Form(default=None),
    total_lessons: int = Form(...),
    package_id: int | None = Form(default=None),
    coach_id: int | None = Form(default=None),
    branch_id: int | None = Form(default=None),
    amount: float = Form(...),
    payment_method: str = Form(...),
    transaction_type: str = Form(default="renewal"),
    course_package_type_code: str | None = Form(default=None),
    course_package_type_label: str | None = Form(default=None),
    note: str | None = Form(default=None),
    receipt: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
) -> dict:
    deleted_ids_sq = select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")
    student: Student | None = None
    if student_id is not None:
        student = db.query(Student).filter(~Student.id.in_(deleted_ids_sq), Student.id == student_id).first()
    elif member_hkid and member_hkid.strip():
        student = get_student_by_hkid_or_404(db, member_hkid.strip())
    elif student_phone and student_phone.strip():
        local = normalize_hk_phone_local_eight(student_phone.strip())
        if not local:
            raise HTTPException(
                status_code=400,
                detail="電話須為香港 8 位手機號碼（請填 +852xxxxxxxx 或只填八位數字）。",
            )
        variants = _hk_phone_lookup_variants(local)
        student = db.query(Student).filter(~Student.id.in_(deleted_ids_sq), Student.phone.in_(variants)).first()
    if student is None:
        raise HTTPException(status_code=400, detail="請提供 student_id、member_hkid 或 student_phone。")
    receipt_tag = student.hkid or student.phone or str(student.id)
    if total_lessons < 1 or total_lessons > 30:
        raise HTTPException(status_code=400, detail="total_lessons must be between 1 and 30.")
    package = db.get(Package, package_id) if package_id else None
    if package_id is not None and (package is None or not package.active):
        raise HTTPException(status_code=400, detail="Invalid package_id.")
    tx_type = transaction_type if transaction_type in {"trial", "new_package", "renewal"} else "renewal"
    kind_code = (course_package_type_code or "").strip() or None
    kind_label = (course_package_type_label or "").strip() or None
    coach = db.get(Coach, coach_id) if coach_id else None
    branch = db.get(Branch, branch_id) if branch_id else None
    receipt_row = None
    if receipt is not None and receipt.filename:
        path = _save_upload_file(receipt, "receipts", receipt_tag, 5 * 1024 * 1024)
        receipt_row = Receipt(
            student_id=student.id,
            member_hkid=(student.hkid or "").strip() or (student.phone or str(student.id)),
            file_path=path,
            amount=amount,
            payment_method=payment_method,
            note=note,
            source="RENEWAL",
        )
        db.add(receipt_row)
        db.flush()
    bal_after = apply_lesson_ledger_delta(
        db,
        student,
        int(total_lessons),
        "renewal_package",
        created_by_role="renewal",
    )
    renewal_row = RenewalRecord(
        student_id=student.id,
        student_name=student.full_name,
        phone=student.phone,
        course_ratio="1:1",
        lessons=int(total_lessons),
        payment_method=payment_method,
        coach_name=coach.full_name if coach else None,
        package_id=package.id if package else None,
        coach_id=coach.id if coach else None,
        branch_id=branch.id if branch else None,
        amount=amount,
        receipt_id=receipt_row.id if receipt_row else None,
        remarks=note,
        applicant_name=student.full_name,
        signature=student.full_name,
        renewal_date=date.today(),
    )
    db.add(renewal_row)
    db.flush()
    detail_obj = {
        "renewal_id": renewal_row.id,
        "package_id": package.id if package else None,
        "total_lessons": int(total_lessons),
        "transaction_type": tx_type,
        "course_package_type_code": kind_code,
        "course_package_type_label": kind_label,
        "amount": amount,
        "payment_method": payment_method,
        "lesson_balance_after": bal_after,
    }
    db.add(AuditLog(action="renewal_create", student_id=student.id, detail=json.dumps(detail_obj, ensure_ascii=False)))
    record_activity(db, student, "renewal_create", renewal_row.id)
    log_whatsapp(
        db,
        student,
        student.phone,
        f"付款已確認（{kind_label or tx_type}）：HKD {amount:g}，已加入 {total_lessons} 堂。PIN 跟 payment/package；請安排第一堂後使用 Course PIN 簽到，剩餘堂數 {bal_after}。",
    )
    log_event(
        "[F002][S003] checkout_summary_created",
        student_id=student.id,
        transaction_type=tx_type,
        course_package_type_code=kind_code,
        amount=amount,
    )
    db.commit()
    return {
        "renewal_id": renewal_row.id,
        "receipt_id": receipt_row.id if receipt_row else None,
        "transaction_type": tx_type,
        "course_package_type_code": kind_code,
        "course_package_type_label": kind_label,
        "total_lessons": int(total_lessons),
        "amount": amount,
        "payment_method": payment_method,
        "lesson_balance_after": bal_after,
        "member": student_to_member_dict(db, student),
    }


@app.post("/api/renewal")
def renewal(payload: RenewalCreate, db: Session = Depends(get_db)) -> dict:
    # region agent log
    _agent_dbg(
        "H5",
        "main.py:renewal",
        "handler_entered",
        {
            "student_id": payload.student_id,
            "phone_len": len((payload.phone or "").strip()),
            "name_len": len((payload.full_name or "").strip()),
        },
    )
    # endregion
    full_name = payload.full_name.strip()
    phone = payload.phone.strip()
    payment_method = payload.payment_method.strip()
    coach_name = payload.coach_name.strip() if payload.coach_name else None
    remarks = payload.remarks.strip() if payload.remarks else None
    applicant_name = payload.applicant_name.strip()
    signature = payload.signature.strip()

    if not full_name or not phone or not payment_method or not applicant_name or not signature:
        raise HTTPException(status_code=400, detail="Required fields cannot be blank.")

    student = db.get(Student, payload.student_id)
    if student is None or _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Student not found.")
    if student.phone.strip() != phone:
        raise HTTPException(status_code=400, detail="Phone does not match the selected student.")
    if student.full_name.strip() != full_name:
        raise HTTPException(status_code=400, detail="Name does not match the selected student.")

    bal_after = apply_lesson_ledger_delta(db, student, int(payload.lessons), "renewal_package", created_by_role="renewal")
    renewal_record = RenewalRecord(
        student_id=student.id,
        student_name=full_name,
        phone=phone,
        course_ratio=payload.course_ratio,
        lessons=int(payload.lessons),
        payment_method=payment_method,
        coach_name=coach_name,
        remarks=remarks,
        applicant_name=applicant_name,
        signature=signature,
        renewal_date=payload.renewal_date,
    )
    db.add(renewal_record)
    db.flush()

    detail_obj = {
        "renewal_id": renewal_record.id,
        "course_ratio": payload.course_ratio,
        "lessons_added": int(payload.lessons),
        "payment_method": payment_method,
        "coach_name": coach_name,
        "renewal_date": payload.renewal_date.isoformat(),
        "lesson_balance_after": bal_after,
    }
    db.add(
        AuditLog(
            action="renewal_submit",
            student_id=student.id,
            detail=json.dumps(detail_obj, ensure_ascii=False),
        )
    )
    log_whatsapp(
        db,
        student,
        student.phone,
        f"續會已確認：已加入 {payload.lessons} 堂，現有餘額 {bal_after} 堂。",
    )

    db.commit()
    db.refresh(student)
    db.refresh(renewal_record)
    return {
        "message": "Renewal submitted",
        "student": {
            "id": student.id,
            "full_name": student.full_name,
            "phone": student.phone,
            "lesson_balance": bal_after,
        },
        "renewal": {
            "id": renewal_record.id,
            "course_ratio": renewal_record.course_ratio,
            "lessons": renewal_record.lessons,
            "payment_method": renewal_record.payment_method,
            "coach_name": renewal_record.coach_name,
            "renewal_date": renewal_record.renewal_date.isoformat(),
        },
    }


@app.get("/api/students")
def list_students(db: Session = Depends(get_db)) -> list[dict]:
    rows = (
        db.query(Student)
        .filter(
            ~Student.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students"))
        )
        .order_by(Student.id.desc())
        .all()
    )
    return [student_to_member_dict(db, row) for row in rows]


# [F007][S001]
# Feature: Backend platform (FastAPI & PostgreSQL)
# Step: Staff session authentication (Bearer token protocol)
# Logic: Login verifies AppUser password, issues AuthSession token; me validates; logout deletes session row.


@app.post("/api/auth/login", response_model=LoginSession)
def auth_login(payload: LoginInput, db: Session = Depends(get_db)) -> LoginSession:
    username = payload.username.strip()
    user = db.query(AppUser).filter(AppUser.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    if not _verify_password(payload.password, user.password_salt, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    token = _new_session_token()
    db.add(
        AuthSession(
            token=token,
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(hours=12),
        )
    )
    db.commit()
    return LoginSession(token=token, username=user.username, role=_login_role_for_response(user))


@app.get("/api/auth/me", response_model=LoginSession)
def auth_me(
    Authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> LoginSession:
    """[F006][S002] Validate the active Bearer session using the same expiry rules as protected routes."""
    token = _parse_auth_header(Authorization)
    if token is None:
        raise HTTPException(status_code=401, detail="Missing auth token.")
    session = (
        db.query(AuthSession, AppUser)
        .join(AuthSession, AuthSession.user_id == AppUser.id)
        .filter(AuthSession.token == token)
        .first()
    )
    if not session:
        raise HTTPException(status_code=401, detail="Invalid auth token.")
    auth_session = session[0]
    user = session[1]
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled.")
    if auth_session.expires_at <= datetime.utcnow():
        db.delete(auth_session)
        db.commit()
        raise HTTPException(status_code=401, detail="Session expired.")
    return LoginSession(token=token, username=user.username, role=_login_role_for_response(user))


@app.post("/api/auth/logout")
def auth_logout(
    Authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> dict:
    token = _parse_auth_header(Authorization)
    if not token:
        return {"message": "Logged out."}
    db.query(AuthSession).filter(AuthSession.token == token).delete(synchronize_session=False)
    db.commit()
    return {"message": "Logged out."}


# [F002][S001]
# Feature: Course Entry & Automation
# Step: Trial course / credit top-up
# Logic: Credits via lesson ledger; API still returns ``lesson_balance`` as SUM(ledger); WhatsApp hook.


@app.post("/api/trial-purchase")
def trial_purchase(payload: TrialPurchaseInput, db: Session = Depends(get_db)) -> dict:
    student = db.query(Student).filter(Student.phone == payload.phone).first()
    if not student:
        raise HTTPException(status_code=404, detail="Student not found.")
    if _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Student not found.")

    bal = apply_lesson_ledger_delta(
        db,
        student,
        payload.credits,
        "trial_purchase",
        created_by_role="trial_purchase",
    )
    log_whatsapp(
        db,
        student,
        student.phone,
        f"Congrats! 你已有 {bal} 堂課餘額。",
    )
    db.commit()
    db.refresh(student)
    return {"message": "Credits added", "lesson_balance": bal}


# [F003][S001]
# Feature: Attendance & Today-Only QR Check-in
# Step: Student PIN verification and lesson redeem
# Logic: resolve_checkin_pin_context; perform_lesson_checkin; optional WS broadcast to coaches.


@app.post("/api/checkin")
async def checkin(payload: CheckinInput, db: Session = Depends(get_db)) -> dict:
    if payload.student_id is not None:
        student = db.query(Student).filter(Student.id == payload.student_id).first()
    else:
        student = db.query(Student).filter(Student.phone == str(payload.phone).strip()).first()
    if student and _is_deleted(db, "students", student.id):
        student = None
    if not student:
        raise HTTPException(status_code=404, detail="Student not found.")
    ctx = resolve_checkin_pin_context(db, student, payload.pin_code)
    if ctx == "blocked_installment_unpaid":
        raise HTTPException(
            status_code=403,
            detail="此方分期 PIN 尚未啟用 — 請先完成該期付款或由櫃台標記已找數後再試。",
        )
    if ctx is None:
        raise HTTPException(status_code=400, detail="Invalid PIN.")
    enrollment, course, coach, pin_kind = ctx
    return await perform_lesson_checkin(
        db,
        student,
        channel="qr_pin",
        resolved_course_enrollment=enrollment,
        resolved_course=course,
        notified_coach=coach,
        pin_resolution=pin_kind,
    )


@app.post("/api/admin/students/{student_id}/manual-redeem")
def admin_manual_redeem_lessons(
    student_id: int,
    payload: ManualLessonRedeemInput,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    """[F003][S005]
    Feature: Attendance & Today-Only QR Check-in
    Step: Staff manual session ledger redeem
    Logic: Deduct lessons without creating Attendance rows, so staff can settle manual/legacy corrections
           while QR check-in remains protected by same-day duplicate guards.
    """
    student = db.query(Student).filter(Student.id == student_id).first()
    if student is None or _is_deleted(db, "students", student_id):
        raise HTTPException(status_code=404, detail="Student not found.")
    before = _lesson_balance_sum(db, student.id)
    if before < payload.lessons:
        raise HTTPException(status_code=400, detail="Student has insufficient remaining lessons.")
    note = (payload.remarks or "").strip() or f"Manual redeem by {user.username}"
    after = before
    for i in range(payload.lessons):
        after = apply_lesson_ledger_delta(
            db,
            student,
            -1,
            payload.reason,
            created_by_role=user.role.lower(),
        )
        db.add(
            CheckinLog(
                student_id=student.id,
                channel="admin_manual_redeem",
                remarks=f"{note} ({i + 1}/{payload.lessons})",
            )
        )
    log_whatsapp(
        db,
        student,
        student.phone,
        f"手動扣堂通知：已扣 {payload.lessons} 堂，剩餘堂數 {after}。",
    )
    db.add(
        AuditLog(
            action="admin_manual_redeem",
            student_id=student.id,
            detail=json.dumps(
                {
                    "lessons": payload.lessons,
                    "before": before,
                    "after": after,
                    "reason": payload.reason,
                    "remarks": payload.remarks,
                    "user": user.username,
                },
                ensure_ascii=False,
            ),
        )
    )
    db.commit()
    db.refresh(student)
    return {
        "ok": True,
        "student": student_to_student_out(db, student).model_dump(mode="json"),
        "redeemed_lessons": payload.lessons,
        "lesson_balance_before": before,
        "lesson_balance_after": after,
    }


@app.post("/api/students/{student_id}/bind-face")
def bind_face(student_id: int, face_id_external: str, db: Session = Depends(get_db)) -> dict:
    student = db.query(Student).filter(Student.id == student_id).first()
    if student is not None and _is_deleted(db, "students", student.id):
        student = None
    if not student:
        raise HTTPException(status_code=404, detail="Student not found.")
    student.face_id_external = face_id_external
    db.commit()
    return {"message": "Face ID linked", "face_id_external": face_id_external}


@app.post("/api/faceid-checkin")
async def faceid_checkin(payload: FaceIdCheckinInput, db: Session = Depends(get_db)) -> dict:
    student = (
        db.query(Student)
        .filter(Student.face_id_external == payload.face_id_external)
        .first()
    )
    if not student:
        raise HTTPException(status_code=404, detail="Face not recognized.")
    if _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Student not found.")
    course, coach = resolve_today_primary_course_for_student(db, student)
    return await perform_lesson_checkin(
        db,
        student,
        channel="hikvision_faceid",
        remarks="simulated",
        resolved_course=course,
        notified_coach=coach,
        pin_resolution="faceid",
    )


# [F002][S001]
# Feature: Course Entry & Automation
# Step: Reference data — packages, branches, coaches, trial classes
# Logic: CRUD and listings feeding admin course-set and coach scheduling UIs.


@app.get("/api/packages", response_model=list[PackageOut])
def list_packages(active: bool | None = True, db: Session = Depends(get_db)) -> list[Package]:
    query = db.query(Package)
    if active is not None:
        query = query.filter(Package.active == active)
    return query.order_by(Package.sessions, Package.id).all()


@app.get("/api/branches", response_model=list[BranchOut])
def list_public_branches(active: bool | None = True, db: Session = Depends(get_db)) -> list[Branch]:
    query = db.query(Branch).filter(~Branch.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "branches")))
    if active is not None:
        query = query.filter(Branch.active == active)
    return query.order_by(Branch.id).all()


@app.post("/api/branches", response_model=BranchOut)
def create_public_branch(payload: BranchCreate, db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)) -> Branch:
    return create_branch(payload, db, user)


@app.patch("/api/branches/{branch_id}", response_model=BranchOut)
def update_public_branch(branch_id: int, payload: BranchUpdate, db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)) -> Branch:
    return update_branch(branch_id, payload, db, user)


@app.get("/api/coaches", response_model=list[CoachOut])
def list_public_coaches(active: bool | None = True, db: Session = Depends(get_db)) -> list[CoachOut]:
    query = db.query(Coach).filter(~Coach.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "coaches")))
    if active is not None:
        query = query.filter(Coach.active == active)
    coaches = query.order_by(Coach.id).all()
    return [coach_row_to_out(db, c) for c in coaches]


@app.post("/api/coaches", response_model=CoachOut)
def create_public_coach(payload: CoachCreate, db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)) -> CoachOut:
    return create_coach(payload, db, user)


@app.patch("/api/coaches/{coach_id}", response_model=CoachOut)
def update_public_coach(coach_id: int, payload: CoachUpdate, db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)) -> CoachOut:
    return update_coach(coach_id, payload, db, user)


@app.get("/api/course-categories")
def list_course_categories_public(db: Session = Depends(get_db)) -> list[dict]:
    """[F011][S001] 報 Course / 試堂 — 只回傳啟用中的 course category。"""
    rows = (
        db.query(CourseCategory)
        .filter(CourseCategory.is_active.is_(True), CourseCategory.is_deleted.is_(False))
        .order_by(CourseCategory.id.asc())
        .all()
    )
    return [{"id": c.id, "name": c.name, "is_active": c.is_active} for c in rows]


@app.post("/api/trial-classes")
def create_trial_class(payload: TrialClassCreate, db: Session = Depends(get_db)) -> dict:
    student = _student_from_trial_class_payload(db, payload)
    category = _resolve_active_course_category(db, payload.course_category_id)
    coach = db.get(Coach, payload.coach_id) if payload.coach_id else None
    branch = db.get(Branch, payload.branch_id) if payload.branch_id else None
    audit = AuditLog(
        action="trial_class_create",
        student_id=student.id,
        coach_id=coach.id if coach else None,
        detail=json.dumps(
            {
                "type": payload.type,
                "course_category_id": category.id,
                "course_category_name": category.name,
                "branch_id": branch.id if branch else None,
                "class_date": payload.class_date.isoformat(),
                "note": (payload.note or "").strip() or None,
            },
            ensure_ascii=False,
        ),
    )
    db.add(audit)
    db.flush()
    record_activity(db, student, "trial_class_create", audit.id)
    db.commit()
    db.refresh(student)
    pins = _course_checkin_pins_for_student(db, student)
    return {
        "id": audit.id,
        "member": student_to_member_dict(db, student),
        "course_checkin_pins": pins,
    }


@app.get("/api/trial-classes")
def list_trial_classes(member_hkid: str | None = None, db: Session = Depends(get_db)) -> list[dict]:
    if member_hkid:
        student = get_student_by_hkid_or_404(db, member_hkid)
        return _trial_records_from_audit(db, student.id)
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.action.in_(("trial_class_create", "coach_trial_quota_grant")))
        .order_by(AuditLog.created_at.desc())
        .limit(200)
        .all()
    )
    if not rows:
        return []
    student_ids = list({r.student_id for r in rows})
    by_student = {sid: _trial_records_from_audit(db, sid) for sid in student_ids}
    out: list[dict] = []
    seen: set[int] = set()
    for row in rows:
        if row.id in seen:
            continue
        seen.add(row.id)
        for item in by_student.get(row.student_id, []):
            if item["id"] == row.id:
                out.append(item)
                break
    return out


@app.post("/api/expenses")
def create_expense(payload: ExpenseCreate, db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)) -> dict:
    row = Expense(date=payload.date, category=payload.category, amount=payload.amount, note=(payload.note or "").strip() or None)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "date": row.date.isoformat(), "category": row.category, "amount": float(row.amount), "note": row.note}


@app.get("/api/finance/summary")
def finance_summary(from_: date | None = Query(default=None, alias="from"), to: date | None = None, db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)) -> dict:
    today = date.today()
    start = from_ or today.replace(day=1)
    end = to or today
    income_rows = db.query(Receipt).filter(func.date(Receipt.created_at) >= start, func.date(Receipt.created_at) <= end).all()
    expense_rows = db.query(Expense).filter(Expense.date >= start, Expense.date <= end).all()
    total_income = sum(float(r.amount or 0) for r in income_rows)
    total_expense = sum(float(e.amount or 0) for e in expense_rows)

    def grouped(items: list[tuple[str, float]]) -> list[dict]:
        totals: dict[str, float] = {}
        for key, amount in items:
            label = key or "未填"
            totals[label] = totals.get(label, 0) + float(amount or 0)
        return [{"key": k, "amount": v} for k, v in sorted(totals.items())]

    renewal_rows = db.query(RenewalRecord).filter(func.date(RenewalRecord.created_at) >= start, func.date(RenewalRecord.created_at) <= end).all()
    branch_names = {b.id: b.name for b in db.query(Branch).all()}
    coach_names = {c.id: c.full_name for c in db.query(Coach).all()}
    daily: dict[str, float] = {}
    for r in income_rows:
        key = r.created_at.date().isoformat()
        daily[key] = daily.get(key, 0) + float(r.amount or 0)
    return {
        "total_income": total_income,
        "total_expense": total_expense,
        "net": total_income - total_expense,
        "txn_count": len(income_rows) + len(expense_rows),
        "by_payment_method": grouped([(r.payment_method or "未填", float(r.amount or 0)) for r in income_rows]),
        "by_branch": grouped([(branch_names.get(r.branch_id, "未填"), float(r.amount or 0)) for r in renewal_rows]),
        "by_coach": grouped([(coach_names.get(r.coach_id, r.coach_name or "未填"), float(r.amount or 0)) for r in renewal_rows]),
        "daily_income": [{"date": k, "amount": v} for k, v in sorted(daily.items())],
    }


# [F004][S001]
# Feature: Admin Reports & Financials
# Step: Admin dashboard KPIs and back-office JSON APIs
# Logic: Summary counts, WhatsApp logs, CSV import/export, hard-delete guards for ADMIN.


@app.get("/api/admin/summary")
def admin_summary(db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)) -> dict:
    total_students = (
        db.query(func.count(Student.id))
        .filter(~Student.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")))
        .scalar()
        or 0
    )
    total_checkins = db.query(func.count(CheckinLog.id)).scalar() or 0
    total_messages = db.query(func.count(WhatsAppLog.id)).scalar() or 0
    audit_rows = db.query(func.count(AuditLog.id)).scalar() or 0
    ledger_positive = (
        select(LessonLedgerEntry.student_id.label("sid"))
        .group_by(LessonLedgerEntry.student_id)
        .having(func.coalesce(func.sum(LessonLedgerEntry.delta_lessons), 0) > 0)
        .subquery()
    )
    active_students = (
        db.query(func.count(Student.id))
        .join(ledger_positive, ledger_positive.c.sid == Student.id)
        .filter(~Student.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")))
        .scalar()
        or 0
    )
    branches = (
        db.query(func.count(Branch.id))
        .filter(~Branch.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "branches")))
        .scalar()
        or 0
    )
    coaches = (
        db.query(func.count(Coach.id))
        .filter(~Coach.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "coaches")))
        .scalar()
        or 0
    )
    courses = (
        db.query(func.count(Course.id))
        .filter(~Course.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "courses")))
        .scalar()
        or 0
    )
    # Category-enrollment installments: distinct students with an active plan, and those still owing a period.
    installment_students_total = (
        db.query(func.count(distinct(CategoryEnrollment.student_id)))
        .join(InstallmentPlan, InstallmentPlan.enrollment_id == CategoryEnrollment.id)
        .filter(InstallmentPlan.status == "active")
        .scalar()
        or 0
    )
    installment_students_unpaid = (
        db.query(func.count(distinct(CategoryEnrollment.student_id)))
        .join(InstallmentPlan, InstallmentPlan.enrollment_id == CategoryEnrollment.id)
        .join(InstallmentPayment, InstallmentPayment.installment_plan_id == InstallmentPlan.id)
        .filter(InstallmentPlan.status == "active")
        .filter(InstallmentPayment.paid_at.is_(None))
        .scalar()
        or 0
    )
    return {
        "total_students": total_students,
        "active_students": active_students,
        "total_checkins": total_checkins,
        "whatsapp_messages": total_messages,
        "audit_logs": audit_rows,
        "branches": branches,
        "coaches": coaches,
        "courses": courses,
        "installment_students_unpaid": installment_students_unpaid,
        "installment_students_total": installment_students_total,
    }


@app.get("/api/admin/course-categories")
def admin_list_course_categories(
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> list[dict]:
    q = db.query(CourseCategory).order_by(CourseCategory.id.asc())
    if not include_deleted:
        q = q.filter(CourseCategory.is_deleted.is_(False))
    return [
        {
            "id": c.id,
            "name": c.name,
            "is_active": c.is_active,
            "is_deleted": c.is_deleted,
            "created_by_role": c.created_by_role,
            "created_at": c.created_at.isoformat(),
        }
        for c in q.all()
    ]


@app.post("/api/admin/course-categories")
def admin_create_course_category(
    payload: CourseCategoryCreate,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    name = payload.name.strip()
    dup = (
        db.query(CourseCategory)
        .filter(CourseCategory.name == name, CourseCategory.is_deleted.is_(False))
        .first()
    )
    if dup:
        raise HTTPException(status_code=409, detail="Category name already exists.")
    role = "ADMIN" if user.role == "ADMIN" else "CLERK"
    row = CourseCategory(name=name, is_active=True, is_deleted=False, created_by_role=role.lower())
    db.add(row)
    db.commit()
    db.refresh(row)
    log_event("course_category_created", category_id=row.id, name=name)
    return {"id": row.id, "name": row.name}


@app.post("/api/admin/course-categories/{category_id}/hide")
def admin_hide_course_category(
    category_id: int,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    row = db.get(CourseCategory, category_id)
    if not row:
        raise HTTPException(status_code=404, detail="Category not found.")
    row.is_deleted = True
    db.commit()
    log_event("course_category_hidden", category_id=category_id)
    return {"id": category_id, "is_deleted": True}


@app.post("/api/admin/course-categories/{category_id}/show")
def admin_show_course_category(
    category_id: int,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    row = db.get(CourseCategory, category_id)
    if not row:
        raise HTTPException(status_code=404, detail="Category not found.")
    row.is_deleted = False
    db.commit()
    log_event("course_category_shown", category_id=category_id)
    return {"id": category_id, "is_deleted": False}


@app.patch("/api/admin/course-categories/{category_id}")
def admin_patch_course_category(
    category_id: int,
    payload: CourseCategoryAdminUpdate,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    """[F011][S001] 課堂和分店管理 — toggle is_active on course category."""
    row = db.get(CourseCategory, category_id)
    if not row or row.is_deleted:
        raise HTTPException(status_code=404, detail="Category not found.")
    data = payload.model_dump(exclude_unset=True)
    if not data:
        raise HTTPException(status_code=400, detail="No fields to update.")
    if "is_active" in data and data["is_active"] is not None:
        row.is_active = bool(data["is_active"])
    db.commit()
    db.refresh(row)
    log_event("course_category_patched", category_id=category_id, is_active=row.is_active)
    return {
        "id": row.id,
        "name": row.name,
        "is_active": row.is_active,
        "is_deleted": row.is_deleted,
        "created_by_role": row.created_by_role,
        "created_at": row.created_at.isoformat(),
    }


@app.post("/api/admin/students/{student_id}/category-enrollment")
def admin_upsert_category_enrollment(
    student_id: int,
    payload: StudentCategoryEnrollmentCreate,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    student = db.get(Student, student_id)
    if not student or _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Student not found.")
    cat = db.get(CourseCategory, payload.course_category_id)
    if not cat or cat.is_deleted:
        raise HTTPException(status_code=400, detail="Invalid or hidden course category.")
    role = user.role.lower()
    existing = (
        db.query(CategoryEnrollment)
        .filter(
            CategoryEnrollment.student_id == student_id,
            CategoryEnrollment.course_category_id == payload.course_category_id,
        )
        .first()
    )
    if existing:
        delta = payload.total_lessons - existing.total_lessons
        if delta != 0:
            existing.total_lessons = payload.total_lessons
            apply_lesson_ledger_delta(
                db,
                student,
                delta,
                "admin_category_lesson_adjust",
                enrollment_id=existing.id,
                created_by_role=role,
            )
        db.commit()
        return {
            "enrollment_id": existing.id,
            "total_lessons": existing.total_lessons,
            "lesson_balance": _lesson_balance_sum(db, student.id),
        }

    enr = CategoryEnrollment(
        student_id=student_id,
        course_category_id=payload.course_category_id,
        status="active",
        started_at=datetime.utcnow().date(),
        total_lessons=payload.total_lessons,
        notes=None,
    )
    db.add(enr)
    db.flush()
    _installment_plan_seed_rows(db, enr.id, payload.total_installments)
    apply_lesson_ledger_delta(
        db,
        student,
        payload.total_lessons,
        "admin_category_enrollment",
        enrollment_id=enr.id,
        created_by_role=role,
    )
    db.add(
        AuditLog(
            action="category_enrollment_create",
            student_id=student.id,
            detail=json.dumps(
                {"enrollment_id": enr.id, "category_id": payload.course_category_id, "lessons": payload.total_lessons},
                ensure_ascii=False,
            ),
        )
    )
    db.commit()
    db.refresh(enr)
    return {
        "enrollment_id": enr.id,
        "total_lessons": enr.total_lessons,
        "lesson_balance": _lesson_balance_sum(db, student.id),
    }


@app.post("/api/admin/students/{student_id}/coach-trial-grant")
def admin_grant_coach_trial_quota(
    student_id: int,
    payload: CoachTrialGrantBody,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    student = db.get(Student, student_id)
    if not student or _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Student not found.")
    q = getattr(student, "coach_trial_quota_remaining", 1)
    if int(q) < 1:
        raise HTTPException(status_code=409, detail="Coach trial quota already used for this student.")
    student.coach_trial_quota_remaining = int(q) - 1
    apply_lesson_ledger_delta(
        db,
        student,
        1,
        "coach_trial_quota",
        created_by_role=user.role.lower(),
    )
    class_date = payload.class_date or datetime.utcnow().date()
    db.add(
        AuditLog(
            action="coach_trial_quota_grant",
            student_id=student.id,
            coach_id=payload.coach_id,
            detail=json.dumps(
                {
                    "type": "coach_quota_1",
                    "branch_id": payload.branch_id,
                    "class_date": class_date.isoformat(),
                    "note": "教練／後台試堂額度（每學生 1 次）",
                },
                ensure_ascii=False,
            ),
        )
    )
    db.commit()
    db.refresh(student)
    log_event("coach_trial_granted", student_id=student_id)
    return {
        "lesson_balance": _lesson_balance_sum(db, student.id),
        "coach_trial_quota_remaining": student.coach_trial_quota_remaining,
    }


@app.get("/api/admin/whatsapp-logs")
def whatsapp_logs(db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)) -> list[dict]:
    logs = db.query(WhatsAppLog).order_by(WhatsAppLog.id.desc()).limit(30).all()
    return [
        {
            "id": item.id,
            "recipient": item.recipient,
            "message": item.message,
            "created_at": item.created_at.isoformat(),
        }
        for item in logs
    ]


@app.get("/api/admin/audit-logs")
def list_audit_logs(
    limit: int = 80, db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> list[dict]:
    limit = min(max(limit, 1), 200)
    rows = (
        db.query(AuditLog, Student, Course, Coach)
        .join(Student, AuditLog.student_id == Student.id)
        .outerjoin(Course, AuditLog.course_id == Course.id)
        .outerjoin(Coach, AuditLog.coach_id == Coach.id)
        .order_by(AuditLog.id.desc())
        .limit(limit)
        .all()
    )
    out: list[dict] = []
    for a, st, c, ch in rows:
        detail_parsed: dict | None = None
        if a.detail:
            try:
                detail_parsed = json.loads(a.detail)
            except json.JSONDecodeError:
                detail_parsed = None
        out.append(
            {
                "id": a.id,
                "created_at": a.created_at.isoformat(),
                "action": a.action,
                "student_id": a.student_id,
                "student_name": st.full_name,
                "course_id": a.course_id,
                "course_title": c.title if c else None,
                "coach_id": a.coach_id,
                "coach_name": ch.full_name if ch else None,
                "coach_phone": ch.phone if ch else None,
                "detail": detail_parsed,
            }
        )
    return out


@app.get("/api/checkins")
def list_checkins(
    checkin_date: date | None = None,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> list[dict]:
    query = db.query(CheckinLog, Student).join(Student, CheckinLog.student_id == Student.id)
    if checkin_date:
        query = query.filter(func.date(CheckinLog.created_at) == checkin_date)

    rows = query.order_by(CheckinLog.created_at.desc()).limit(200).all()
    return [
        {
            "id": checkin.id,
            "student_id": student.id,
            "student_name": student.full_name,
            "student_phone": student.phone,
            "channel": checkin.channel,
            "remarks": checkin.remarks,
            "created_at": checkin.created_at.isoformat(),
        }
        for checkin, student in rows
    ]


# --- Branches ---


@app.get("/api/admin/branches", response_model=list[BranchOut])
def list_branches(db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)) -> list[Branch]:
    return (
        db.query(Branch)
        .filter(~Branch.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "branches")))
        .order_by(Branch.id)
        .all()
    )


@app.post("/api/admin/branches", response_model=BranchOut)
def create_branch(
    payload: BranchCreate, db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> Branch:
    data = payload.model_dump()
    data["name"] = data["name"].strip()
    data["address"] = data["address"].strip()
    data["remarks"] = data["remarks"].strip() if data.get("remarks") else None
    data["code"] = allocate_branch_code(db, data.get("code"), data["name"])
    if not data["name"] or not data["address"]:
        raise HTTPException(status_code=400, detail="Branch name and address are required.")
    b = Branch(**data)
    db.add(b)
    db.commit()
    db.refresh(b)
    return b


@app.patch("/api/admin/branches/{branch_id}", response_model=BranchOut)
def update_branch(
    branch_id: int,
    payload: BranchUpdate,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> Branch:
    branch = db.query(Branch).filter(Branch.id == branch_id).first()
    if not branch or _is_deleted(db, "branches", branch.id):
        raise HTTPException(status_code=404, detail="Branch not found.")
    data = payload.model_dump(exclude_unset=True)
    if not data:
        raise HTTPException(status_code=400, detail="No fields to update.")
    for key in ("name", "address", "business_start_time", "business_end_time", "remarks", "active"):
        if key not in data:
            continue
        val = data[key]
        if isinstance(val, str):
            val = val.strip()
        if key in {"name", "address"}:
            if not val:
                raise HTTPException(status_code=400, detail=f"{key} cannot be empty.")
        if key == "remarks" and isinstance(val, str) and val == "":
            val = None
        setattr(branch, key, val)
    db.commit()
    db.refresh(branch)
    return branch


@app.get("/api/admin/branches/export.csv")
def export_branches_csv(
    db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> PlainTextResponse:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "address", "code", "business_start_time", "business_end_time", "remarks"])
    for row in (
        db.query(Branch)
        .filter(~Branch.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "branches")))
        .order_by(Branch.id)
        .all()
    ):
        w.writerow(
            [
                row.name,
                row.address,
                row.code,
                row.business_start_time,
                row.business_end_time,
                row.remarks or "",
            ]
        )
    return PlainTextResponse(
        buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="branches.csv"'},
    )


@app.post("/api/admin/branches/import")
def import_branches_csv(
    file: UploadFile = File(...), db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> dict:
    raw = file.file.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(raw))
    added = 0
    skipped = 0
    for row in reader:
        name = (row.get("name") or "").strip()
        address = (row.get("address") or "").strip()
        code = (row.get("code") or "").strip() or None
        start = (row.get("business_start_time") or "09:00").strip() or "09:00"
        end = (row.get("business_end_time") or "22:00").strip() or "22:00"
        remarks = (row.get("remarks") or "").strip() or None
        if not name or not address:
            skipped += 1
            continue
        dup_name = (
            db.query(Branch)
            .filter(Branch.name == name)
            .filter(_active_branches_filter())
            .first()
        )
        if dup_name:
            skipped += 1
            continue
        branch_code = allocate_branch_code(db, code, name)
        db.add(
            Branch(
                name=name,
                address=address,
                code=branch_code,
                business_start_time=start,
                business_end_time=end,
                remarks=remarks,
            )
        )
        added += 1
    db.commit()
    return {"imported": added, "skipped": skipped}


# --- Coaches ---


@app.get("/api/admin/coaches")
def list_coaches(
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
    q: str | None = Query(default=None, description="搜尋關鍵字"),
    search_by: str = Query(default="name", description="name 或 phone"),
) -> list[CoachOut]:
    query = db.query(Coach).filter(~Coach.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "coaches")))
    raw_q = (q or "").strip()
    if raw_q:
        esc = raw_q.replace("\\", "").replace("%", "").replace("_", "")
        pattern = f"%{esc}%"
        if (search_by or "name").strip().lower() == "phone":
            query = query.filter(Coach.phone.ilike(pattern))
        else:
            query = query.filter(Coach.full_name.ilike(pattern))
    coaches = query.order_by(Coach.id).all()
    en_by_coach = _enrolled_students_for_coaches(db, [c.id for c in coaches])
    return [coach_row_to_out(db, c, enrolled_students=en_by_coach.get(c.id, [])) for c in coaches]


@app.post("/api/admin/coaches", response_model=CoachOut)
def create_coach(
    payload: CoachCreate, db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> CoachOut:
    if db.query(Coach).filter(Coach.phone == payload.phone).first():
        raise HTTPException(status_code=409, detail="Coach phone already exists.")
    if payload.branch_id is not None:
        if not db.query(Branch).filter(
            Branch.id == payload.branch_id,
            ~Branch.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "branches")),
        ).first():
            raise HTTPException(status_code=400, detail="Invalid branch_id.")
    data = payload.model_dump()
    if data.get("hire_date") is None:
        data["hire_date"] = date.today()
    c = Coach(**data)
    db.add(c)
    db.commit()
    db.refresh(c)
    en_map = _enrolled_students_for_coaches(db, [c.id])
    return coach_row_to_out(db, c, enrolled_students=en_map.get(c.id, []))


@app.patch("/api/admin/coaches/{coach_id}", response_model=CoachOut)
def update_coach(
    coach_id: int,
    payload: CoachUpdate,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> CoachOut:
    coach = db.query(Coach).filter(Coach.id == coach_id).first()
    if not coach or _is_deleted(db, "coaches", coach.id):
        raise HTTPException(status_code=404, detail="Coach not found.")

    data = payload.model_dump(exclude_unset=True)
    if not data:
        raise HTTPException(status_code=400, detail="No fields to update.")

    if "phone" in data and data["phone"]:
        other = (
            db.query(Coach)
            .filter(Coach.phone == data["phone"], Coach.id != coach_id)
            .first()
        )
        if other:
            raise HTTPException(status_code=409, detail="Coach phone already exists.")

    if "branch_id" in data:
        bid = data["branch_id"]
        if bid is not None:
            if not db.query(Branch).filter(
                Branch.id == bid,
                ~Branch.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "branches")),
            ).first():
                raise HTTPException(status_code=400, detail="Invalid branch_id.")
        coach.branch_id = bid

    if "full_name" in data and data["full_name"] is not None:
        coach.full_name = data["full_name"].strip()
    if "phone" in data and data["phone"]:
        coach.phone = data["phone"].strip()
    if "specialty" in data:
        coach.specialty = data["specialty"].strip() if data["specialty"] else None
    if "active" in data and data["active"] is not None:
        coach.active = bool(data["active"])
    if "hire_date" in data:
        coach.hire_date = data["hire_date"]

    db.commit()
    db.refresh(coach)
    en_map = _enrolled_students_for_coaches(db, [coach.id])
    return coach_row_to_out(db, coach, enrolled_students=en_map.get(coach.id, []))


@app.get("/api/admin/coaches/export.csv")
def export_coaches_csv(
    db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> PlainTextResponse:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["full_name", "phone", "branch_code", "hire_date"])
    for coach in (
        db.query(Coach)
        .filter(~Coach.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "coaches")))
        .order_by(Coach.id)
        .all()
    ):
        code = ""
        if coach.branch_id:
            br = db.query(Branch).filter(Branch.id == coach.branch_id).first()
            code = br.code if br else ""
        hd = coach.hire_date.isoformat() if coach.hire_date else ""
        w.writerow([coach.full_name, coach.phone, code, hd])
    return PlainTextResponse(
        buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="coaches.csv"'},
    )


@app.post("/api/admin/coaches/import")
def import_coaches_csv(
    file: UploadFile = File(...), db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> dict:
    raw = file.file.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(raw))
    added = 0
    for row in reader:
        full_name = (row.get("full_name") or "").strip()
        phone = (row.get("phone") or "").strip()
        branch_code = (row.get("branch_code") or "").strip() or None
        hire_raw = (row.get("hire_date") or "").strip()
        hire_d: date | None = None
        if hire_raw:
            try:
                hire_d = date.fromisoformat(hire_raw[:10])
            except ValueError:
                hire_d = None
        if not full_name or not phone:
            continue
        if db.query(Coach).filter(Coach.phone == phone).first():
            continue
        branch_id = None
        if branch_code:
            br = db.query(Branch).filter(Branch.code == branch_code).first()
            if br:
                branch_id = br.id
        db.add(
            Coach(
                full_name=full_name,
                phone=phone,
                branch_id=branch_id,
                hire_date=hire_d if hire_d is not None else date.today(),
            )
        )
        added += 1
    db.commit()
    return {"imported": added}


# -----------------------------------------------------------------------------
# Students CSV — PostgreSQL table ``zomate_fs_students``
# GET ``/api/admin/students/export.csv`` · POST ``/api/admin/students/import``
# Column layout shared with Next.js mock routes when API base is empty (dev only).
# Auth: ``require_admin_or_clerk``.
# -----------------------------------------------------------------------------


@app.get("/api/admin/students/export.csv")
def export_students_csv(
    db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> PlainTextResponse:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "full_name",
            "phone",
            "hkid",
            "date_of_birth",
            "email",
            "health_notes",
            "disclaimer_accepted",
            "lesson_balance",
            "face_id_external",
            "created_at",
        ]
    )
    for s in (
        db.query(Student)
        .filter(~Student.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")))
        .order_by(Student.id)
        .all()
    ):
        w.writerow(
            [
                s.full_name,
                s.phone,
                s.hkid or "",
                s.date_of_birth.isoformat() if s.date_of_birth else "",
                s.email or "",
                s.health_notes or "",
                "1" if s.disclaimer_accepted else "0",
                _lesson_balance_sum(db, s.id),
                s.face_id_external or "",
                s.created_at.isoformat(),
            ]
        )
    return PlainTextResponse(
        buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="students.csv"'},
    )


@app.post("/api/admin/students/import")
def import_students_csv(
    file: UploadFile = File(...), db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> dict:
    """批次新增／更新：僅當 CSV 的姓名（標準化）與電話（八位／+852 變體）皆與同一筆學員吻合時才更新；電話已存在但姓名不同則略過。"""
    raw = file.file.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(raw))
    added = 0
    updated = 0
    skipped = 0
    active_students_sq = ~Student.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students"))

    for row in reader:
        full_name = (row.get("full_name") or "").strip()
        phone_raw = (row.get("phone") or "").strip()
        hkid_raw = (row.get("hkid") or "").strip()
        hkid_norm = normalize_hkid(hkid_raw) if hkid_raw else None
        dob_raw = (row.get("date_of_birth") or "").strip()
        try:
            dob = date.fromisoformat(dob_raw) if dob_raw else None
        except ValueError:
            skipped += 1
            continue
        email = (row.get("email") or "").strip() or None
        health_notes = (row.get("health_notes") or "").strip() or None
        disc = (row.get("disclaimer_accepted") or "1").strip() in ("1", "true", "True", "yes")
        try:
            balance = int((row.get("lesson_balance") or "0").strip() or 0)
        except ValueError:
            balance = 0
        face = (row.get("face_id_external") or "").strip() or None

        local_eight = normalize_hk_phone_local_eight(phone_raw) if phone_raw else None
        variants = _hk_phone_lookup_variants(local_eight) if local_eight else []

        existing: Student | None = None
        if variants:
            existing = db.query(Student).filter(active_students_sq, Student.phone.in_(variants)).first()

        if existing is not None:
            csv_name_key = _normalize_student_csv_name(full_name)
            if not csv_name_key:
                skipped += 1
                continue
            if _normalize_student_csv_name(existing.full_name) != csv_name_key:
                skipped += 1
                continue
            if full_name:
                existing.full_name = full_name.strip()
            if hkid_norm:
                other_hk = (
                    db.query(Student)
                    .filter(active_students_sq, Student.hkid == hkid_norm, Student.id != existing.id)
                    .first()
                )
                if other_hk:
                    skipped += 1
                    continue
                existing.hkid = hkid_norm
            if dob is not None:
                existing.date_of_birth = dob
            existing.email = email
            existing.health_notes = health_notes
            existing.disclaimer_accepted = disc
            ledger_sum = _lesson_balance_sum(db, existing.id)
            adj = int(balance) - ledger_sum
            if adj != 0:
                db.add(
                    LessonLedgerEntry(
                        student_id=existing.id,
                        enrollment_id=None,
                        delta_lessons=adj,
                        reason="admin_csv_import",
                        created_by_role=user.role.lower(),
                    )
                )
                db.flush()
            existing.face_id_external = face
            if local_eight:
                existing.phone = f"+852{local_eight}"
            updated += 1
            continue

        if not full_name or not local_eight:
            skipped += 1
            continue

        canonical = f"+852{local_eight}"
        if hkid_norm:
            hk_dup = db.query(Student).filter(active_students_sq, Student.hkid == hkid_norm).first()
            if hk_dup:
                skipped += 1
                continue

        st = Student(
            full_name=full_name,
            phone=canonical,
            hkid=hkid_norm,
            date_of_birth=dob,
            email=email,
            health_notes=health_notes,
            disclaimer_accepted=disc,
            face_id_external=face,
        )
        db.add(st)
        db.flush()
        if balance != 0:
            db.add(
                LessonLedgerEntry(
                    student_id=st.id,
                    enrollment_id=None,
                    delta_lessons=balance,
                    reason="admin_csv_import_new",
                    created_by_role=user.role.lower(),
                )
            )
            db.flush()
        added += 1

    db.commit()
    return {"imported": added, "updated": updated, "skipped": skipped}


@app.delete("/api/admin/students/{student_id}")
def delete_student(
    student_id: int,
    hard: bool = False,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    student = db.query(Student).filter(Student.id == student_id).first()
    if not student or _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Student not found.")

    if hard and user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only ADMIN can hard delete.")

    if hard:
        db.query(CourseEnrollment).filter(CourseEnrollment.student_id == student.id).delete(synchronize_session=False)
        db.query(CheckinLog).filter(CheckinLog.student_id == student.id).delete(synchronize_session=False)
        db.query(WhatsAppLog).filter(WhatsAppLog.student_id == student.id).delete(synchronize_session=False)
        db.query(AuditLog).filter(AuditLog.student_id == student.id).delete(synchronize_session=False)
        db.delete(student)
    else:
        _record_soft_delete(db, "students", student.id, user)
    db.commit()
    return {"ok": True, "student_id": student.id, "hard": bool(hard)}


@app.delete("/api/admin/branches/{branch_id}")
def delete_branch(
    branch_id: int,
    hard: bool = False,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    branch = db.query(Branch).filter(Branch.id == branch_id).first()
    if not branch or _is_deleted(db, "branches", branch.id):
        raise HTTPException(status_code=404, detail="Branch not found.")

    if hard and user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only ADMIN can hard delete.")

    if hard:
        if db.query(Course).filter(Course.branch_id == branch.id).first():
            raise HTTPException(
                status_code=409,
                detail="Cannot hard delete: this branch has linked courses. Soft delete or remove courses first.",
            )
        db.delete(branch)
    else:
        _record_soft_delete(db, "branches", branch.id, user)
    db.commit()
    return {"ok": True, "branch_id": branch.id, "hard": bool(hard)}


@app.delete("/api/admin/coaches/{coach_id}")
def delete_coach(
    coach_id: int,
    hard: bool = False,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    coach = db.query(Coach).filter(Coach.id == coach_id).first()
    if not coach or _is_deleted(db, "coaches", coach.id):
        raise HTTPException(status_code=404, detail="Coach not found.")

    if hard and user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only ADMIN can hard delete.")

    if hard:
        if db.query(Course).filter(Course.coach_id == coach.id).first():
            raise HTTPException(
                status_code=409,
                detail="Cannot hard delete: this coach has linked courses. Soft delete or reassign courses first.",
            )
        db.delete(coach)
    else:
        _record_soft_delete(db, "coaches", coach.id, user)
    db.commit()
    return {"ok": True, "coach_id": coach.id, "hard": bool(hard)}


@app.delete("/api/admin/courses/{course_id}")
def delete_course(
    course_id: int,
    hard: bool = False,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    course = db.query(Course).filter(Course.id == course_id).first()
    if not course or _is_deleted(db, "courses", course.id):
        raise HTTPException(status_code=404, detail="Course not found.")

    if hard and user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only ADMIN can hard delete.")

    if hard:
        db.query(CourseEnrollment).filter(CourseEnrollment.course_id == course.id).delete(synchronize_session=False)
        db.delete(course)
    else:
        _record_soft_delete(db, "courses", course.id, user)
    db.commit()
    return {"ok": True, "course_id": course.id, "hard": bool(hard)}


@app.get("/api/admin/qrcode-pdf")
def download_qrcode_pdf(
    request: Request,
    kind: str,
    origin: str | None = None,
    payload: str | None = None,
) -> Response:
    kind_map = {
        "onboard": "onboard",
        "checkin": "checkin",
        "payload": "payload",
    }
    if kind not in kind_map:
        raise HTTPException(status_code=400, detail="Invalid kind.")

    base = (origin or str(request.base_url).rstrip("/")).rstrip("/")
    if kind == "onboard":
        data = f"{base}/student/onboard"
        name = "onboard_qr.pdf"
        label = "Registration"
    elif kind == "checkin":
        data = payload or f"{base}/student/checkin?from=qr"
        label = "Check-In"
        name = "checkin_qr.pdf"
    else:
        data = payload or json.dumps({"type": "zomate_checkin", "v": 1})
        label = "Check-In (JSON)"
        name = "checkin_payload_qr.pdf"

    pdf = _build_qr_code_pdf_bytes(label=label, payload=data)
    headers = {"Content-Disposition": f'attachment; filename="{name}"'}
    return Response(content=pdf, media_type="application/pdf", headers=headers)


# -----------------------------------------------------------------------------
# Attendance: CSV template only (batch import pipeline TBD)
# -----------------------------------------------------------------------------


@app.get("/api/admin/attendance/template.csv")
def export_attendance_template_csv(user: AppUser = Depends(require_admin_or_clerk)) -> PlainTextResponse:
    """CSV template for attendance workflows (stored/processed server-side later)."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["student_name", "phone", "pin", "checkin_time_iso"])
    w.writerow(["Larry Lo", "+85291234567", "12345", "2026-04-26T10:00:00Z"])
    return PlainTextResponse(
        buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="attendance-template.csv"'},
    )


# -----------------------------------------------------------------------------
# NEXT.js-compatible report mocks (PostgreSQL-backed where applicable).
# Frontend uses NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 with these paths.
# -----------------------------------------------------------------------------

_V1_SALES_ROWS: list[dict] = [
    {
        "date": "2026-04-02",
        "clientName": "Chan Tai Man",
        "courseType": "PT 10",
        "amount": 8800,
        "coachName": "Coach A",
        "paymentStatus": "PAID_FULL",
        "installmentStatus": "NONE",
    },
    {
        "date": "2026-04-18",
        "clientName": "Lee Siu Ming",
        "courseType": "PT 30",
        "amount": 22800,
        "coachName": "Coach B",
        "paymentStatus": "INSTALLMENT_ACTIVE",
        "installmentStatus": "ACTIVE",
    },
    {
        "date": "2026-04-22",
        "clientName": "Wong Ka Yan",
        "courseType": "Trial → PT 10",
        "amount": 1280,
        "coachName": "Coach A",
        "paymentStatus": "PENDING",
        "installmentStatus": "NONE",
    },
]

_V1_EXPENSE_ROWS: list[dict] = [
    {
        "id": "e1",
        "category": "Rent",
        "amount": 28000,
        "date": "2026-04-01",
        "memo": "Studio rent",
        "invoiceRef": "INV-R-001",
    },
    {
        "id": "e2",
        "category": "Utilities",
        "amount": 1200,
        "date": "2026-04-05",
        "memo": "Electricity",
        "invoiceRef": "",
    },
]

_V1_LEDGER_ROWS: list[dict] = [
    {
        "studentName": "Larry Lo",
        "sessionStartIso": datetime.utcnow().isoformat() + "Z",
        "reason": "attended",
        "notes": "Ledger seed · FastAPI",
    }
]


# [F004][S001]
# Feature: Admin Reports & Financials
# Step: v1 reports — sales, expenses, coach-attendance rollups
# Logic: JSON rows for TanStack tables; coach-attendance joins check-in audit events.


@app.get("/api/v1/reports/sales")
def v1_reports_sales(
    sort: str | None = None,
    columns: str | None = None,
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    rows = list(_V1_SALES_ROWS)
    if sort:
        part = sort.split(",")[0]
        if ":" in part:
            col, direction = part.split(":", 1)
            desc = direction.lower() == "desc"
            if col == "amount":
                rows.sort(key=lambda r: r.get("amount", 0), reverse=desc)
            elif col == "date":
                rows.sort(key=lambda r: r.get("date", ""), reverse=desc)
            elif col in ("clientName", "courseType", "coachName", "paymentStatus", "installmentStatus"):
                rows.sort(key=lambda r: str(r.get(col, "")).lower(), reverse=desc)
    meta: dict[str, object] = {"source": "fastapi", "sort": sort or ""}
    if columns:
        meta["columns"] = columns
    return {"rows": rows, "meta": meta}


@app.get("/api/v1/reports/expenses")
def v1_reports_expenses_get(user: AppUser = Depends(require_admin_or_clerk)) -> dict:
    return {"rows": list(_V1_EXPENSE_ROWS)}


@app.post("/api/v1/reports/expenses")
def v1_reports_expenses_post(payload: dict, user: AppUser = Depends(require_admin_or_clerk)) -> dict:
    cat = payload.get("category")
    amt = payload.get("amount")
    if not isinstance(amt, (int, float)) or not cat:
        raise HTTPException(status_code=400, detail="category and amount required")
    nid = f"e{len(_V1_EXPENSE_ROWS) + 1}-{secrets.token_hex(4)}"
    row = {
        "id": nid,
        "category": str(cat),
        "amount": float(amt),
        "date": str(payload.get("date") or datetime.utcnow().date().isoformat()),
        "memo": str(payload.get("memo") or ""),
        "invoiceRef": str(payload.get("invoiceRef") or ""),
    }
    _V1_EXPENSE_ROWS.append(row)
    return {"ok": True, "row": row}


@app.get("/api/v1/reports/coach-attendance")
def v1_reports_coach_attendance(
    month: str | None = None,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> dict:
    q = (
        db.query(AuditLog, Student, Course, Coach)
        .join(Student, AuditLog.student_id == Student.id)
        .outerjoin(Course, AuditLog.course_id == Course.id)
        .outerjoin(Coach, AuditLog.coach_id == Coach.id)
        .filter(AuditLog.action == "checkin_redeem")
    )
    if month and len(month) >= 7 and month[4] == "-":
        try:
            y = int(month[:4])
            mo = int(month[5:7])
            range_start = datetime(y, mo, 1)
            range_end_excl = datetime(y + (1 if mo == 12 else 0), (1 if mo == 12 else mo + 1), 1)
            q = q.filter(AuditLog.created_at >= range_start, AuditLog.created_at < range_end_excl)
        except ValueError:
            pass
    tuples = q.order_by(AuditLog.created_at.desc()).limit(2000).all()
    detail_rows: list[dict[str, object]] = []
    coach_buckets: dict[tuple[str, str], dict[str, float]] = {}
    for a, st, course, coach in tuples:
        coach_name = coach.full_name if coach else ""
        st_d = ""
        ed = ""
        ctitle = ""
        if course:
            ctitle = course.title or ""
            st_d = course.series_start_date.isoformat() if course.series_start_date else course.scheduled_start.date().isoformat()
            ed = course.series_end_date.isoformat() if course.series_end_date else course.scheduled_end.date().isoformat()
            dur_h = max(
                0.25,
                (course.scheduled_end - course.scheduled_start).total_seconds() / 3600.0,
            )
        else:
            dur_h = 1.0
        ym = a.created_at.strftime("%Y-%m")
        ck = (coach_name, ym)
        if ck not in coach_buckets:
            coach_buckets[ck] = {"hours": 0.0, "classes": 0.0}
        coach_buckets[ck]["hours"] += dur_h
        coach_buckets[ck]["classes"] += 1.0
        detail_rows.append(
            {
                "studentName": st.full_name,
                "courseName": ctitle,
                "sessionTimeIso": a.created_at.isoformat(),
                "coachName": coach_name,
                "courseStartDate": st_d,
                "courseEndDate": ed,
            }
        )
    summary_rows: list[dict[str, object]] = []
    for (cname, mon), agg in sorted(coach_buckets.items(), key=lambda x: (x[0][0], x[0][1])):
        hrs = agg["hours"]
        cls_ct = int(agg["classes"])
        summary_rows.append(
            {
                "coachName": cname or "—",
                "month": mon,
                "classesTaught": cls_ct,
                "hoursOnFloor": round(hrs, 2),
                "grossPayHkd": int(hrs * 450),
            }
        )
    return {"rows": detail_rows, "summary": summary_rows, "month": month}


# [F003][S005]
# Feature: Attendance & Today-Only QR Check-in
# Step: Session ledger — deduct reasons and admin adjustments
# Logic: GET lists ledger rows; POST inserts adjustment entry (demo-seeded in dev).


@app.get("/api/v1/session-ledger")
def v1_session_ledger_get(user: AppUser = Depends(require_admin_or_clerk)) -> dict:
    return {"entries": list(_V1_LEDGER_ROWS)}


@app.post("/api/v1/session-ledger")
def v1_session_ledger_post(payload: dict, user: AppUser = Depends(require_admin_or_clerk)) -> dict:
    req = payload or {}
    if not req.get("studentName"):
        raise HTTPException(status_code=400, detail="studentName required")
    _V1_LEDGER_ROWS.insert(
        0,
        {
            "studentName": str(req["studentName"]),
            "sessionStartIso": str(req.get("sessionStartIso") or datetime.utcnow().isoformat() + "Z"),
            "reason": str(req.get("reason") or "attended"),
            "notes": str(req.get("notes") or ""),
        },
    )
    return {"ok": True}


# --- Courses (admin + coach) ---


@app.get("/api/admin/courses", response_model=list[CourseOut])
def admin_list_courses(db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)) -> list[CourseOut]:
    courses = (
        db.query(Course)
        .options(
            joinedload(Course.branch),
            joinedload(Course.coach),
            joinedload(Course.enrollments).joinedload(CourseEnrollment.student),
        )
        .filter(~Course.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "courses")))
        .order_by(Course.scheduled_start.desc())
        .limit(200)
        .all()
    )
    return [course_to_out(c) for c in courses]


@app.get("/api/admin/courses/by-day", response_model=list[CourseOut])
def admin_courses_by_day(
    day: date = Query(..., description="Calendar day (Hong Kong) to match against course lesson dates."),
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> list[CourseOut]:
    # [F009][S003]
    # Feature: Scheduled course & enrollment PINs
    # Step: Staff lists courses that fall on ``day`` for coach assignment UI.
    courses_raw = (
        db.query(Course)
        .options(
            joinedload(Course.branch),
            joinedload(Course.coach),
            joinedload(Course.enrollments).joinedload(CourseEnrollment.student),
        )
        .filter(~Course.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "courses")))
        .order_by(Course.scheduled_start.asc())
        .limit(800)
        .all()
    )
    picked = [c for c in courses_raw if day in get_lesson_dates_for_course(c)]
    return [course_to_out(c) for c in picked]


@app.post("/api/admin/courses", response_model=CourseOut)
def admin_create_course(
    payload: CourseCreate, db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> CourseOut:
    if not db.query(Branch).filter(
        Branch.id == payload.branch_id,
        ~Branch.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "branches")),
    ).first():
        raise HTTPException(status_code=400, detail="Invalid branch_id.")
    coach = db.query(Coach).filter(
        Coach.id == payload.coach_id,
        ~Coach.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "coaches")),
    ).first()
    if not coach:
        raise HTTPException(status_code=400, detail="Invalid coach_id.")

    start_d = payload.course_start_date or payload.scheduled_start.date()
    ws = list(payload.lesson_weekdays)
    lesson_dates = enumerate_lesson_dates(start_d, ws, payload.total_lessons)
    if not lesson_dates:
        raise HTTPException(status_code=400, detail="Could not schedule lessons from the given start date.")
    series_end = lesson_dates[-1]
    dur = payload.scheduled_end - payload.scheduled_start
    first_start = datetime.combine(lesson_dates[0], payload.scheduled_start.time())
    first_end = first_start + dur

    course = Course(
        title=payload.title,
        branch_id=payload.branch_id,
        coach_id=payload.coach_id,
        scheduled_start=first_start,
        scheduled_end=first_end,
        total_lessons=payload.total_lessons,
        lesson_weekdays=",".join(str(x) for x in ws),
        series_start_date=lesson_dates[0],
        series_end_date=series_end,
    )
    db.add(course)
    db.flush()

    branch = course.branch
    first_for_coach_notice: Student | None = None
    enrolled_names: list[str] = []
    n_inst = max(1, min(5, getattr(payload, "total_installments", 1)))
    segment_ranges = _lesson_segment_ranges(payload.total_lessons, n_inst)

    for sid in payload.student_ids:
        student = db.query(Student).filter(Student.id == sid).first()
        if not student:
            continue
        if (
            db.query(CourseEnrollment)
            .filter(
                CourseEnrollment.course_id == course.id,
                CourseEnrollment.student_id == student.id,
            )
            .first()
        ):
            continue
        if _is_deleted(db, "students", student.id):
            continue
        seg_payload: list[dict] = []
        seg_json: str | None = None
        if n_inst <= 1:
            primary_pin = allocate_enrollment_pin(db, course.id, student.id)
        else:
            batch_reserved: set[str] = set()
            for idx, (lo, hi) in enumerate(segment_ranges):
                p = allocate_enrollment_pin(db, course.id, student.id, avoid_pins=frozenset(batch_reserved))
                batch_reserved.add(p)
                seg_payload.append(
                    {
                        "installment_no": idx + 1,
                        "lesson_from": lo,
                        "lesson_to": hi,
                        "pin": p,
                        "paid": idx == 0,
                    }
                )
            seg_json = json.dumps(seg_payload, ensure_ascii=False)
            primary_pin = str(seg_payload[0]["pin"])
        db.add(
            CourseEnrollment(
                course_id=course.id,
                student_id=student.id,
                checkin_pin=primary_pin,
                segment_pins_json=seg_json,
            )
        )
        enrolled_names.append(student.full_name)
        if first_for_coach_notice is None:
            first_for_coach_notice = student
        pkg_sessions = payload.total_lessons
        if pkg_sessions > 0:
            apply_lesson_ledger_delta(
                db,
                student,
                pkg_sessions,
                "course_open_package",
                created_by_role=user.role.lower(),
            )
        bal_msg = _lesson_balance_sum(db, student.id)
        if n_inst <= 1:
            pin_txt = (
                f" 你嘅課堂簽到 PIN：{primary_pin}"
                "（一次付款此等套餐為一個 PIN；續約／新一筆過數會派新 PIN）。"
            )
        else:
            pin_txt = (
                " 分期簽到 PIN："
                + "；".join(
                    f"第{r['installment_no']}個分期（第{r['lesson_from']}–{r['lesson_to']}堂）PIN {r['pin']}"
                    for r in seg_payload
                )
                + "。（首期預設可簽到；第2期起需先確認收款，並由櫃台 PATCH 或使用後台標記為已付先有得簽該 PIN。）"
            )
        msg = (
            f"課堂確認：{payload.title} @ {branch.name} "
            f"首課 {first_start.strftime('%Y-%m-%d %H:%M')}，套餐共 {payload.total_lessons} 堂，預計最後一堂 {series_end.isoformat()}。"
            f"{pin_txt}"
            f" 餘額已加 {pkg_sessions} 堂（套餐堂數），現有 {bal_msg} 堂。"
        )
        log_whatsapp(db, student, student.phone, msg)

    if first_for_coach_notice is not None:
        # [F002][S003] Coach WhatsApp log — baseline + optional agreed first session + confirm with students.
        note_trim = (payload.coach_schedule_note or "").strip()
        lines = [
            f"【後台開課】{payload.title} · {branch.name}",
            f"教練 {coach.full_name}：學員「{'、'.join(enrolled_names)}」已編入此課程。",
            f"系統首課基準時段：{first_start.strftime('%Y-%m-%d %H:%M')}（請務必同學員核實實際到店／首堂時間）。",
        ]
        if payload.student_first_session_at is not None:
            lines.append(
                "櫃台記錄與學員約定首課："
                f"{payload.student_first_session_at.strftime('%Y-%m-%d %H:%M')}。"
            )
        if note_trim:
            lines.append(f"備註：{note_trim}")
        lines.append("請主動約學員確認第一堂時間、地點及準備事項。")
        log_whatsapp(db, first_for_coach_notice, coach.phone, "\n".join(lines))

    db.commit()
    db.refresh(course)
    full = (
        db.query(Course)
        .options(
            joinedload(Course.branch),
            joinedload(Course.coach),
            joinedload(Course.enrollments).joinedload(CourseEnrollment.student),
        )
        .filter(Course.id == course.id)
        .first()
    )
    assert full is not None
    return course_to_out(full)


@app.patch("/api/admin/courses/{course_id}/installment-paid", response_model=CourseOut)
def admin_course_mark_installment_paid(
    course_id: int,
    payload: CourseInstallmentMarkPaid,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> CourseOut:
    """[F002][S002]
    Feature: Course Entry & Automation
    Step: Unlock scheduled-package installment PIN after staff confirms payment
    Logic: Sets ``paid: true`` on matching segment in ``segment_pins_json`` — check-in rejects unpaid segments.
    """
    if _is_deleted(db, "courses", course_id):
        raise HTTPException(status_code=404, detail="Course not found.")
    enr = (
        db.query(CourseEnrollment)
        .filter(
            CourseEnrollment.course_id == course_id,
            CourseEnrollment.student_id == payload.student_id,
        )
        .first()
    )
    if not enr:
        raise HTTPException(status_code=404, detail="Enrollment not found.")
    raw = getattr(enr, "segment_pins_json", None)
    if not raw:
        raise HTTPException(status_code=400, detail="This enrollment has no installment PIN segments.")
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Corrupt installment segment payload.") from exc
    if not isinstance(rows, list):
        raise HTTPException(status_code=500, detail="Invalid installment segment payload.")
    touched = False
    for row in rows:
        if isinstance(row, dict) and int(row.get("installment_no") or 0) == payload.installment_no:
            row["paid"] = True
            touched = True
            break
    if not touched:
        raise HTTPException(status_code=404, detail="Installment segment not found for this enrollment.")
    enr.segment_pins_json = json.dumps(rows, ensure_ascii=False)
    db.commit()
    full = (
        db.query(Course)
        .options(
            joinedload(Course.branch),
            joinedload(Course.coach),
            joinedload(Course.enrollments).joinedload(CourseEnrollment.student),
        )
        .filter(Course.id == course_id)
        .first()
    )
    if full is None or _is_deleted(db, "courses", full.id):
        raise HTTPException(status_code=404, detail="Course not found.")
    return course_to_out(full)


@app.patch("/api/admin/courses/{course_id}/assign-coach", response_model=CourseOut)
def admin_assign_course_coach(
    course_id: int,
    payload: CourseAssignCoach,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> CourseOut:
    # [F009][S003]
    # Feature: Scheduled course & enrollment PINs
    # Step: Staff reassigns ``Course.coach_id`` for the coach timetable UI.
    course = db.query(Course).filter(Course.id == course_id).first()
    if not course or _is_deleted(db, "courses", course.id):
        raise HTTPException(status_code=404, detail="Course not found.")
    coach = db.query(Coach).filter(
        Coach.id == payload.coach_id,
        ~Coach.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "coaches")),
    ).first()
    if not coach:
        raise HTTPException(status_code=400, detail="Invalid coach_id.")
    course.coach_id = payload.coach_id
    db.commit()
    full = (
        db.query(Course)
        .options(
            joinedload(Course.branch),
            joinedload(Course.coach),
            joinedload(Course.enrollments).joinedload(CourseEnrollment.student),
        )
        .filter(Course.id == course_id)
        .first()
    )
    assert full is not None
    return course_to_out(full)


@app.get("/api/coach/courses", response_model=list[CourseOut])
# CF09:CoachCalendarCourses — Bearer：ADMIN／CLERK／COACH；COACH 僅 slug 對應之 coach_id（見 ``_coach_user_may_access_coach_row``）。
def coach_list_courses(
    coach_id: int,
    day: date | None = None,
    from_date: date | None = None,
    to_date: date | None = None,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_staff_for_coach_routes),
) -> list[CourseOut]:
    coach_row = db.query(Coach).filter(Coach.id == coach_id).first()
    if not coach_row or _is_deleted(db, "coaches", coach_id):
        raise HTTPException(status_code=404, detail="Coach not found.")
    if not _coach_user_may_access_coach_row(db, user, coach_row):
        raise HTTPException(status_code=403, detail="This coach schedule is not linked to your login.")
    q = (
        db.query(Course)
        .options(
            joinedload(Course.branch),
            joinedload(Course.coach),
            joinedload(Course.enrollments).joinedload(CourseEnrollment.student),
        )
        .filter(
            Course.coach_id == coach_id,
            ~Course.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "courses")),
        )
    )
    limit_n = 400 if (from_date is not None and to_date is not None or day is not None) else 200
    courses_raw = q.order_by(Course.scheduled_start.asc()).limit(800).all()
    if day:
        courses = [c for c in courses_raw if day in get_lesson_dates_for_course(c)][:limit_n]
    elif from_date is not None and to_date is not None:
        if to_date < from_date:
            raise HTTPException(status_code=400, detail="to_date must be >= from_date.")
        picked: list[Course] = []
        for c in courses_raw:
            for ld in get_lesson_dates_for_course(c):
                if from_date <= ld <= to_date:
                    picked.append(c)
                    break
        courses = picked[:limit_n]
    else:
        courses = courses_raw[:limit_n]
    return [course_to_out(c) for c in courses]


@app.patch("/api/coach/courses/{course_id}", response_model=CourseOut)
# CF09:CoachCalendarReschedule — 與 GET 相同：Bearer ADMIN／CLERK／COACH；COACH 僅可操作 slug 綁定之 coach_id。
def coach_reschedule_course(
    course_id: int,
    coach_id: int,
    payload: CourseReschedule,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_staff_for_coach_routes),
) -> CourseOut:
    coach_row = db.query(Coach).filter(Coach.id == coach_id).first()
    if not coach_row or _is_deleted(db, "coaches", coach_id):
        raise HTTPException(status_code=404, detail="Coach not found.")
    if not _coach_user_may_access_coach_row(db, user, coach_row):
        raise HTTPException(status_code=403, detail="This coach schedule is not linked to your login.")
    course = db.query(Course).filter(Course.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found.")
    if _is_deleted(db, "courses", course.id):
        raise HTTPException(status_code=404, detail="Course not found.")
    if course.coach_id != coach_id:
        raise HTTPException(status_code=403, detail="This class is not assigned to this coach.")
    course.scheduled_start = payload.scheduled_start
    course.scheduled_end = payload.scheduled_end
    db.commit()
    full = (
        db.query(Course)
        .options(
            joinedload(Course.branch),
            joinedload(Course.coach),
            joinedload(Course.enrollments).joinedload(CourseEnrollment.student),
        )
        .filter(Course.id == course_id)
        .first()
    )
    assert full is not None
    return course_to_out(full)
