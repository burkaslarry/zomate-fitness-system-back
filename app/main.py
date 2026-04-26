import csv
import io
import json
import hashlib
import hmac
import os
import secrets
from datetime import date, datetime, timedelta

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import func, or_, select
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
    Student,
    WhatsAppLog,
)
from .schemas import (
    BranchCreate,
    BranchOut,
    CheckinInput,
    CoachCreate,
    CoachOut,
    CourseCreate,
    CourseEnrollmentOut,
    CourseOut,
    CourseReschedule,
    FaceIdCheckinInput,
    LoginInput,
    LoginSession,
    StudentOnboardCreate,
    StudentOut,
    TrialPurchaseInput,
)

app = FastAPI(title="Zomate Fitness System Demo API")

def _cors_origins_from_env() -> list[str]:
    raw = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
    defaults = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
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
    canvas.setFont("Helvetica", 14)
    canvas.drawString(40, 810, "Zomate Fitness QR Code")
    canvas.setFont("Helvetica", 10)
    canvas.drawString(40, 788, f"用途：{label}")
    canvas.drawString(40, 768, f"內容：{payload[:150]}")
    canvas.drawImage(
        ImageReader(qr_buffer),
        (width - 260) / 2,
        300,
        width=260,
        height=260,
        preserveAspectRatio=True,
        mask="auto",
    )
    canvas.setFont("Helvetica", 9)
    canvas.drawString(40, 50, "Scan this QR code with your mobile device.")
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


def resolve_today_primary_course_for_student(
    db: Session, student: Student, now: datetime | None = None
) -> tuple[Course | None, Coach | None]:
    """Pick one class today for coach notification when using account PIN / FaceID (not class PIN)."""
    now = now or datetime.utcnow()
    today = now.date()
    rows = (
        db.query(Course, Coach)
        .join(CourseEnrollment, CourseEnrollment.course_id == Course.id)
        .join(Coach, Coach.id == Course.coach_id)
        .filter(
            CourseEnrollment.student_id == student.id,
            func.date(Course.scheduled_start) == today,
            ~Course.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "courses")),
            ~Coach.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "coaches")),
        )
        .all()
    )
    if not rows:
        return None, None
    if len(rows) == 1:
        return rows[0][0], rows[0][1]
    for course, coach in rows:
        if course.scheduled_start <= now <= course.scheduled_end:
            return course, coach
    best = min(rows, key=lambda r: abs((r[0].scheduled_start - now).total_seconds()))
    return best[0], best[1]


def resolve_checkin_pin_context(
    db: Session, student: Student, pin: str
) -> tuple[Course | None, Coach | None, str] | None:
    """Class PIN → that course's coach only. Account PIN → today's primary course heuristic."""
    pin = pin.strip()
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
        return c, c.coach, "class_pin"
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
        _seed_default_users(db)
        db.commit()
    finally:
        db.close()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/public/student-search")
def public_student_search(q: str = "", db: Session = Depends(get_db)) -> list[dict]:
    """Kiosk-friendly search after QR scan (name or phone fragment)."""
    raw = (q or "").strip()
    if len(raw) < 1:
        return []
    if len(raw) > 64:
        raise HTTPException(status_code=400, detail="Query too long")
    pattern = f"%{raw}%"
    rows = (
        db.query(Student)
        .filter(~Student.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "students")))
        .filter(
            or_(
                Student.full_name.ilike(pattern),
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
    if db.query(Branch).filter(Branch.code == payload.code).first():
        raise HTTPException(status_code=409, detail="Branch code already exists.")
    b = Branch(**payload.model_dump())
    db.add(b)
    db.commit()
    db.refresh(b)
    return b


@app.get("/api/admin/branches/export.csv")
def export_branches_csv(
    db: Session = Depends(get_db), user: AppUser = Depends(require_admin_or_clerk)
) -> PlainTextResponse:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "address", "code"])
    for row in (
        db.query(Branch)
        .filter(~Branch.id.in_(select(DeletedRecord.entity_id).where(DeletedRecord.entity_type == "branches")))
        .order_by(Branch.id)
        .all()
    ):
        w.writerow([row.name, row.address, row.code])
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
    for row in reader:
        name = (row.get("name") or "").strip()
        address = (row.get("address") or "").strip()
        code = (row.get("code") or "").strip()
        if not name or not address or not code:
            continue
        if db.query(Branch).filter(Branch.code == code).first():
            continue
        db.add(Branch(name=name, address=address, code=code))
        added += 1
    db.commit()
    return {"imported": added}


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


# --- Students CSV ---


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
    raw = file.file.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(raw))
    added = 0
    skipped = 0
    for row in reader:
        full_name = (row.get("full_name") or "").strip()
        phone = (row.get("phone") or "").strip()
        if not full_name or not phone:
            skipped += 1
            continue
        if db.query(Student).filter(Student.phone == phone).first():
            skipped += 1
            continue
        email = (row.get("email") or "").strip() or None
        health_notes = (row.get("health_notes") or "").strip() or None
        disc = (row.get("disclaimer_accepted") or "1").strip() in ("1", "true", "True", "yes")
        pin_raw = (row.get("pin_code") or "").strip()
        pin = allocate_student_pin(db, pin_raw if pin_raw else None)
        try:
            balance = int((row.get("lesson_balance") or "0").strip() or 0)
        except ValueError:
            balance = 0
        face = (row.get("face_id_external") or "").strip() or None
        db.add(
            Student(
                full_name=full_name,
                phone=phone,
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
    return {"imported": added, "skipped": skipped}


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
    user: AppUser = Depends(require_admin_or_clerk),
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
        label = "新學生入職"
    elif kind == "checkin":
        data = payload or f"{base}/student/checkin?from=qr"
        label = "核心簽到入口"
        name = "checkin_qr.pdf"
    else:
        data = payload or json.dumps({"type": "zomate_checkin", "v": 1})
        label = "簽到 JSON"
        name = "checkin_payload_qr.pdf"

    pdf = _build_qr_code_pdf_bytes(label=label, payload=data)
    headers = {"Content-Disposition": f'attachment; filename="{name}"'}
    return Response(content=pdf, media_type="application/pdf", headers=headers)


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

    course = Course(
        title=payload.title,
        branch_id=payload.branch_id,
        coach_id=payload.coach_id,
        scheduled_start=payload.scheduled_start,
        scheduled_end=payload.scheduled_end,
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
            f"{payload.scheduled_start.strftime('%Y-%m-%d %H:%M')}。"
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
    if day:
        q = q.filter(
            func.date(Course.scheduled_start) == day,
        )
    courses = q.order_by(Course.scheduled_start.asc()).limit(200).all()
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
