import calendar
import csv
import io
import json
import hashlib
import hmac
import os
import secrets
from datetime import date, datetime, timedelta, timezone

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session, joinedload
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen.canvas import Canvas
import qrcode

from .database import Base, engine, get_db
from .models import (
    AuditLog,
    Branch,
    CheckinLog,
    Coach,
    Course,
    CourseEnrollment,
    DeletedRecord,
    AppUser,
    AuthSession,
    RenewalRecord,
    Student,
    WhatsAppLog,
)
from .schemas import (
    BranchCreate,
    BranchUpdate,
    BranchOut,
    CheckinInput,
    CoachCreate,
    CoachOut,
    CoachUpdate,
    CourseCreate,
    CourseEnrollmentOut,
    CourseOut,
    CourseReschedule,
    FaceIdCheckinInput,
    LoginInput,
    LoginSession,
    RenewalCreate,
    StudentOnboardCreate,
    StudentOut,
    StudentRegisterV1,
    TrialPurchaseInput,
)

# -----------------------------------------------------------------------------
# Zomate Fitness — FastAPI service (zomate-fitness-system-back)
#
# REST + WebSocket; PostgreSQL tables ``zomate_fs_*``. Admin CSV import/export
# (students, branches, coaches), attendance CSV template. Bearer auth (ADMIN /
# CLERK). CORS: CORS_ALLOWED_ORIGINS.
#
# Ops: GET /health, GET /health/db · GET /api/health, GET /api/health/db (probes & Swagger).
#
# Swagger UI: GET /docs · ReDoc: GET /redoc · OpenAPI JSON: GET /openapi.json
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


@app.on_event("startup")
def _agent_log_renewal_route_registered() -> None:
    paths = [getattr(r, "path", "") for r in app.routes if getattr(r, "path", None)]
    _agent_dbg(
        "H4",
        "main.py:startup",
        "renewal_route_probe",
        {"renewal_in_routes": "/api/renewal" in paths, "nroutes": len(paths)},
    )


@app.get("/", include_in_schema=False)
def root_redirect_to_docs() -> RedirectResponse:
    """Landing：導向 Swagger UI。"""
    return RedirectResponse(url="/docs")

def _cors_origins_from_env() -> list[str]:
    raw = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
    defaults = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "https://zomate-fitness-system-front.vercel.app",
    ]
    if not raw:
        return defaults
    parsed = [item.strip() for item in raw.split(",") if item.strip()]
    return parsed or defaults


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins_from_env(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
# 03. get_current_user / require_* 透過依賴注入實作 ADMIN / CLERK 權限控制


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
    users = [
        ("masterzoe", "12345678", "ADMIN"),
        ("worker", "12347890", "CLERK"),
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


def require_admin_or_clerk(user: AppUser = Depends(get_current_user)) -> AppUser:
    if user.role not in {"ADMIN", "CLERK"}:
        raise HTTPException(status_code=403, detail="Role not allowed.")
    return user


def require_admin(user: AppUser = Depends(get_current_user)) -> AppUser:
    if user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only ADMIN allowed.")
    return user


def log_whatsapp(db: Session, student: Student, recipient: str, message: str) -> None:
    log = WhatsAppLog(student_id=student.id, recipient=recipient, message=message)
    db.add(log)


def allocate_student_pin(db: Session, preferred: str | None) -> str:
    if preferred:
        taken = db.query(Student).filter(Student.pin_code == preferred).first()
        if taken:
            raise HTTPException(status_code=409, detail="PIN already in use. Leave blank for auto.")
        return preferred
    for _ in range(80):
        pin = f"{secrets.randbelow(90000) + 10000}"
        if not db.query(Student).filter(Student.pin_code == pin).first():
            return pin
    raise HTTPException(status_code=500, detail="Could not allocate a unique PIN.")


def allocate_enrollment_pin(db: Session, course_id: int) -> str:
    for _ in range(80):
        pin = f"{secrets.randbelow(90000) + 10000}"
        taken = (
            db.query(CourseEnrollment)
            .filter(
                CourseEnrollment.course_id == course_id,
                CourseEnrollment.checkin_pin == pin,
            )
            .first()
        )
        if not taken:
            return pin
    raise HTTPException(status_code=500, detail="Could not allocate class PIN.")


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
        f"Digital signature (step 3): {payload.digital_signature.strip()}",
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
    ]
    try:
        for s in stmts:
            db.execute(text(s))
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
    if count < 1:
        return []
    wd_set = set(w for w in weekdays if 0 <= w <= 6)
    if not wd_set:
        wd_set = {start.weekday()}
    dates: list[date] = []
    d = start
    guard = 0
    while len(dates) < count and guard < 800:
        if d.weekday() in wd_set:
            dates.append(d)
            if len(dates) >= count:
                break
        d += timedelta(days=1)
        guard += 1
    return dates


def get_lesson_dates_for_course(course: Course) -> list[date]:
    ws = parse_lesson_weekdays_str(course.lesson_weekdays)
    start = course.series_start_date or course.scheduled_start.date()
    try:
        n = int(course.total_lessons)
    except (TypeError, ValueError):
        n = 1
    n = max(1, min(10, n))
    if n <= 1 and (not getattr(course, "lesson_weekdays", None) or course.lesson_weekdays == "0"):
        return [course.scheduled_start.date()]
    return enumerate_lesson_dates(start, ws, n)


def course_active_at_now(course: Course, now: datetime) -> bool:
    d = now.date()
    if d not in get_lesson_dates_for_course(course):
        return False
    t_start = course.scheduled_start.time()
    t_end = course.scheduled_end.time()
    t = now.time()
    if t_start <= t_end:
        return t_start <= t <= t_end
    return t >= t_start or t <= t_end


def resolve_today_primary_course_for_student(
    db: Session, student: Student, now: datetime | None = None
) -> tuple[Course | None, Coach | None]:
    """Pick one class today when using account PIN / FaceID (not class PIN)."""
    now = now or datetime.utcnow()
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
) -> tuple[Course | None, Coach | None, str] | None:
    """Class PIN → that course's coach only when today's date matches a scheduled lesson day."""
    pin = pin.strip()
    now = datetime.utcnow()
    enr = (
        db.query(CourseEnrollment)
        .options(
            joinedload(CourseEnrollment.course).joinedload(Course.coach),
        )
        .filter(CourseEnrollment.student_id == student.id, CourseEnrollment.checkin_pin == pin)
        .filter(~CourseEnrollment.course_id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "courses")))
        .first()
    )
    if enr:
        c = enr.course
        if now.date() in get_lesson_dates_for_course(c):
            return c, c.coach, "class_pin"
        return None
    if student.pin_code == pin:
        c, coach = resolve_today_primary_course_for_student(db, student)
        return c, coach, "account_pin"
    return None


def course_to_out(course: Course) -> CourseOut:
    branch = course.branch
    coach = course.coach
    enrollments: list[CourseEnrollmentOut] = []
    for e in course.enrollments:
        st = e.student
        enrollments.append(
            CourseEnrollmentOut(
                student_id=st.id,
                student_name=st.full_name,
                student_phone=st.phone,
                checkin_pin=e.checkin_pin,
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


async def perform_lesson_checkin(
    db: Session,
    student: Student,
    channel: str,
    remarks: str | None = None,
    *,
    resolved_course: Course | None = None,
    notified_coach: Coach | None = None,
    pin_resolution: str = "unknown",
) -> dict:
    if student.lesson_balance <= 0:
        raise HTTPException(status_code=400, detail="Student has no remaining lessons.")

    student.lesson_balance -= 1
    checkin_log = CheckinLog(student_id=student.id, channel=channel, remarks=remarks)
    db.add(checkin_log)
    db.flush()

    log_whatsapp(
        db,
        student,
        student.phone,
        f"上堂通知：{student.full_name} 已簽到，剩餘堂數 {student.lesson_balance}。",
    )
    coach_msg = f"教練通知：學生 {student.full_name} 已簽到。"
    if notified_coach:
        log_whatsapp(db, student, notified_coach.phone, coach_msg)
    else:
        log_whatsapp(db, student, "coach-demo", coach_msg)

    detail_obj: dict = {
        "channel": channel,
        "pin_resolution": pin_resolution,
        "lesson_balance_after": student.lesson_balance,
        "checkin_id": checkin_log.id,
        "course_title": resolved_course.title if resolved_course else None,
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
        "lesson_balance": student.lesson_balance,
        "channel": channel,
        "created_at": checkin_log.created_at.isoformat(),
    }
    await manager.broadcast_json(event_payload)

    return {
        "message": "Check-in success",
        "student": {
            "id": student.id,
            "full_name": student.full_name,
            "phone": student.phone,
            "lesson_balance": student.lesson_balance,
            "channel": channel,
        },
        "notified_coach": (
            {"id": notified_coach.id, "full_name": notified_coach.full_name, "phone": notified_coach.phone}
            if notified_coach
            else None
        ),
        "resolved_course_id": resolved_course.id if resolved_course else None,
    }


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    db = next(get_db())
    try:
        _migrate_branch_extended_columns(db)
        _migrate_courses_extended_columns(db)
        _seed_default_branches(db)
        _seed_default_users(db)
        db.commit()
    finally:
        db.close()


API_SERVICE_NAME = "zomate-fitness-api"


def _health_liveness_payload() -> dict:
    return {"status": "ok", "service": API_SERVICE_NAME}


def _health_database_payload(db: Session) -> dict:
    db.execute(text("SELECT 1"))
    return {"status": "ok", "database": "connected", "service": API_SERVICE_NAME}


# -----------------------------------------------------------------------------
# Health & DB connectivity (deploy probes, local smoke tests, Swagger · tags=health)
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
            "lesson_balance": s.lesson_balance,
        }
        for s in rows
    ]


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


@app.post("/api/onboarding", response_model=StudentOut)
def onboarding(payload: StudentOnboardCreate, db: Session = Depends(get_db)) -> StudentOut:
    existing = db.query(Student).filter(Student.phone == payload.phone).first()
    if existing:
        raise HTTPException(status_code=409, detail="Phone already exists.")

    pin = allocate_student_pin(db, payload.pin_code)
    data = payload.model_dump()
    data["pin_code"] = pin
    student = Student(**data)
    db.add(student)
    db.commit()
    db.refresh(student)
    return student


@app.post("/api/v1/students/register")
def register_student_v1(payload: StudentRegisterV1, db: Session = Depends(get_db)) -> dict:
    """F01 multi-step wizard — persist to PostgreSQL + return PIN + membership expiry."""
    phone = payload.phone.strip()
    existing = db.query(Student).filter(Student.phone == phone).first()
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
        if payload.email is not None:
            existing.email = (payload.email.strip() or None)
        existing.disclaimer_accepted = True
        existing.lesson_balance = int(existing.lesson_balance) + int(payload.package_sessions)
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
            phone,
            f"續會登記已收到：已加 {payload.package_sessions} 堂，現有餘額 {existing.lesson_balance} 堂，PIN 不變（{existing.pin_code}）。",
        )
        db.commit()
        db.refresh(existing)
        return {"pin_code": existing.pin_code, "membership_expiry_iso": expiry_iso}

    if payload.form_type == "renewal":
        raise HTTPException(
            status_code=404,
            detail="找不到此電話之學籍。請改選「新人申請」或核對號碼。",
        )

    pin = allocate_student_pin(db, None)
    student = Student(
        full_name=payload.full_name.strip(),
        phone=phone,
        email=(payload.email or "").strip() or None,
        health_notes=_register_v1_health_notes(payload),
        disclaimer_accepted=True,
        pin_code=pin,
        lesson_balance=int(payload.package_sessions),
    )
    db.add(student)
    db.flush()
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
        phone,
        f"歡迎 {student.full_name}！你的簽到 PIN 是 {student.pin_code}，已存入 {payload.package_sessions} 堂。",
    )
    db.commit()
    db.refresh(student)
    return {"pin_code": student.pin_code, "membership_expiry_iso": expiry_iso}


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

    student.lesson_balance += int(payload.lessons)
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
        "lesson_balance_after": student.lesson_balance,
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
        f"續會已確認：已加入 {payload.lessons} 堂，現有餘額 {student.lesson_balance} 堂。",
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
            "lesson_balance": student.lesson_balance,
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


@app.get("/api/students", response_model=list[StudentOut])
def list_students(db: Session = Depends(get_db)) -> list[StudentOut]:
    return (
        db.query(Student)
        .filter(
            ~Student.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students"))
        )
        .order_by(Student.id.desc())
        .all()
    )


@app.post("/api/auth/login", response_model=LoginSession)
# CF10: Authentication flow.
# Steps:
# 01. 驗證帳號密碼後建立隨機 session token
# 02. 回傳 token, username, role 給前端儲存
# 03. /api/auth/me 與 /api/auth/logout 使用同一 token 協議
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
    return LoginSession(token=token, username=user.username, role="ADMIN" if user.role == "ADMIN" else "CLERK")


@app.get("/api/auth/me", response_model=LoginSession)
def auth_me(
    Authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> LoginSession:
    token = _parse_auth_header(Authorization)
    session = (
        db.query(AppUser)
        .join(AuthSession, AuthSession.user_id == AppUser.id)
        .filter(AuthSession.token == token)
        .first()
    )
    if not session:
        raise HTTPException(status_code=401, detail="Invalid auth token.")
    user = session
    return LoginSession(token=token or "", username=user.username, role="ADMIN" if user.role == "ADMIN" else "CLERK")


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


@app.post("/api/trial-purchase")
def trial_purchase(payload: TrialPurchaseInput, db: Session = Depends(get_db)) -> dict:
    student = db.query(Student).filter(Student.phone == payload.phone).first()
    if not student:
        raise HTTPException(status_code=404, detail="Student not found.")
    if _is_deleted(db, "students", student.id):
        raise HTTPException(status_code=404, detail="Student not found.")

    student.lesson_balance += payload.credits
    log_whatsapp(
        db,
        student,
        student.phone,
        f"Congrats! 你已有 {student.lesson_balance} 堂課餘額。",
    )
    db.commit()
    db.refresh(student)
    return {"message": "Credits added", "lesson_balance": student.lesson_balance}


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
    if ctx is None:
        raise HTTPException(status_code=400, detail="Invalid PIN.")
    course, coach, pin_kind = ctx
    return await perform_lesson_checkin(
        db,
        student,
        channel="qr_pin",
        resolved_course=course,
        notified_coach=coach,
        pin_resolution=pin_kind,
    )


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
    active_students = (
        db.query(func.count(Student.id))
        .filter(~Student.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")))
        .filter(Student.lesson_balance > 0)
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
    return {
        "total_students": total_students,
        "active_students": active_students,
        "total_checkins": total_checkins,
        "whatsapp_messages": total_messages,
        "audit_logs": audit_rows,
        "branches": branches,
        "coaches": coaches,
        "courses": courses,
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
    for key in ("name", "address", "business_start_time", "business_end_time", "remarks"):
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


@app.get("/api/admin/coaches", response_model=list[CoachOut])
def list_coaches(db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)) -> list[Coach]:
    return (
        db.query(Coach)
        .filter(~Coach.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "coaches")))
        .order_by(Coach.id)
        .all()
    )


@app.post("/api/admin/coaches", response_model=CoachOut)
def create_coach(
    payload: CoachCreate, db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> Coach:
    if db.query(Coach).filter(Coach.phone == payload.phone).first():
        raise HTTPException(status_code=409, detail="Coach phone already exists.")
    if payload.branch_id is not None:
        if not db.query(Branch).filter(
            Branch.id == payload.branch_id,
            ~Branch.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "branches")),
        ).first():
            raise HTTPException(status_code=400, detail="Invalid branch_id.")
    c = Coach(**payload.model_dump())
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@app.patch("/api/admin/coaches/{coach_id}", response_model=CoachOut)
def update_coach(
    coach_id: int,
    payload: CoachUpdate,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> Coach:
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

    db.commit()
    db.refresh(coach)
    return coach


@app.get("/api/admin/coaches/export.csv")
def export_coaches_csv(
    db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> PlainTextResponse:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["full_name", "phone", "branch_code"])
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
        w.writerow([coach.full_name, coach.phone, code])
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
        if not full_name or not phone:
            continue
        if db.query(Coach).filter(Coach.phone == phone).first():
            continue
        branch_id = None
        if branch_code:
            br = db.query(Branch).filter(Branch.code == branch_code).first()
            if br:
                branch_id = br.id
        db.add(Coach(full_name=full_name, phone=phone, branch_id=branch_id))
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
            "email",
            "health_notes",
            "disclaimer_accepted",
            "pin_code",
            "lesson_balance",
            "face_id_external",
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
                s.email or "",
                s.health_notes or "",
                "1" if s.disclaimer_accepted else "0",
                s.pin_code,
                s.lesson_balance,
                s.face_id_external or "",
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
    """Upsert by **full_name**: same姓名 → replace欄位；新姓名 insert（phone 必填且不可與其他人重複）。"""
    raw = file.file.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(raw))
    added = 0
    updated = 0
    skipped = 0
    active_students_sq = ~Student.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students"))

    for row in reader:
        full_name = (row.get("full_name") or "").strip()
        if not full_name:
            skipped += 1
            continue

        phone_raw = (row.get("phone") or "").strip()
        email = (row.get("email") or "").strip() or None
        health_notes = (row.get("health_notes") or "").strip() or None
        disc = (row.get("disclaimer_accepted") or "1").strip() in ("1", "true", "True", "yes")
        pin_raw = (row.get("pin_code") or "").strip()
        try:
            balance = int((row.get("lesson_balance") or "0").strip() or 0)
        except ValueError:
            balance = 0
        face = (row.get("face_id_external") or "").strip() or None

        existing = (
            db.query(Student)
            .filter(active_students_sq, Student.full_name == full_name)
            .first()
        )

        if existing is not None:
            if phone_raw:
                other = (
                    db.query(Student)
                    .filter(active_students_sq, Student.phone == phone_raw, Student.id != existing.id)
                    .first()
                )
                if other:
                    skipped += 1
                    continue
                existing.phone = phone_raw
            if pin_raw:
                try:
                    existing.pin_code = allocate_student_pin(db, pin_raw)
                except HTTPException:
                    skipped += 1
                    continue
            existing.email = email
            existing.health_notes = health_notes
            existing.disclaimer_accepted = disc
            existing.lesson_balance = balance
            existing.face_id_external = face
            updated += 1
            continue

        if not phone_raw:
            skipped += 1
            continue
        if db.query(Student).filter(active_students_sq, Student.phone == phone_raw).first():
            skipped += 1
            continue

        try:
            pin = allocate_student_pin(db, pin_raw if pin_raw else None)
        except HTTPException:
            skipped += 1
            continue

        db.add(
            Student(
                full_name=full_name,
                phone=phone_raw,
                email=email,
                health_notes=health_notes,
                disclaimer_accepted=disc,
                pin_code=pin,
                lesson_balance=balance,
                face_id_external=face,
            )
        )
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
        pin = allocate_enrollment_pin(db, course.id)
        db.add(
            CourseEnrollment(course_id=course.id, student_id=student.id, checkin_pin=pin)
        )
        if payload.credits_on_enroll > 0:
            student.lesson_balance += payload.credits_on_enroll
        msg = (
            f"課堂確認：{payload.title} @ {branch.name} "
            f"首課 {first_start.strftime('%Y-%m-%d %H:%M')}，套餐共 {payload.total_lessons} 堂，預計最後一堂 {series_end.isoformat()}。"
            f" 你嘅課堂簽到 PIN：{pin}（亦可用帳戶 PIN 簽到）。"
            f" 餘額已加 {payload.credits_on_enroll} 堂，現有 {student.lesson_balance} 堂。"
        )
        log_whatsapp(db, student, student.phone, msg)

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


@app.get("/api/coach/courses", response_model=list[CourseOut])
def coach_list_courses(
    coach_id: int,
    day: date | None = None,
    from_date: date | None = None,
    to_date: date | None = None,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> list[CourseOut]:
    if not db.query(Coach).filter(Coach.id == coach_id).first():
        raise HTTPException(status_code=404, detail="Coach not found.")
    if _is_deleted(db, "coaches", coach_id):
        raise HTTPException(status_code=404, detail="Coach not found.")
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
def coach_reschedule_course(
    course_id: int,
    coach_id: int,
    payload: CourseReschedule,
    db: Session = Depends(get_db),
    user: AppUser = Depends(require_admin_or_clerk),
) -> CourseOut:
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
