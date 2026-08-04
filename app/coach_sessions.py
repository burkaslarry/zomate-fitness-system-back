"""[F008][S002]
Feature: Coach Session Management
Step: Filtered session query and export helpers
Logic: Expand enrollments into per-session rows with category resolution and attendance.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, time

from sqlalchemy.orm import Session, joinedload

from .enrollment_schedule import get_lesson_dates_for_enrollment
from .models import Attendance, CategoryEnrollment, CourseCategory, CourseEnrollment
from .timezone import hk_calendar_date, now_hk, utc_to_hk


def coach_skill_category_ids(db: Session, coach_id: int) -> list[int]:
    """[F008][S001] Category ids assigned to coach via skills table."""
    from .models import CoachSkill

    return [
        int(row[0])
        for row in (
            db.query(CoachSkill.course_category_id)
            .filter(CoachSkill.coach_id == coach_id)
            .order_by(CoachSkill.course_category_id.asc())
            .all()
        )
    ]


def resolve_enrollment_category(
    db: Session, enr: CourseEnrollment, *, skill_ids: set[int] | None = None
) -> tuple[int | None, str | None]:
    """[F008][S001] Map scheduled enrollment to course category via CategoryEnrollment or title."""
    if skill_ids is None:
        skill_ids = set(coach_skill_category_ids(db, enr.coach_id))

    cat_rows = (
        db.query(CategoryEnrollment)
        .options(joinedload(CategoryEnrollment.course_category))
        .filter(
            CategoryEnrollment.student_id == enr.student_id,
            CategoryEnrollment.status == "active",
        )
        .all()
    )
    best: tuple[int | None, str | None] = (None, None)
    for ce in cat_rows:
        if ce.course_category_id not in skill_ids:
            continue
        name = ce.course_category.name
        if name in enr.title:
            return ce.course_category_id, name
        if best[0] is None:
            best = (ce.course_category_id, name)

    if best[0] is not None:
        return best

    cats = (
        db.query(CourseCategory)
        .filter(CourseCategory.is_active.is_(True), CourseCategory.is_deleted.is_(False))
        .order_by(CourseCategory.id.asc())
        .all()
    )
    for cat in sorted(cats, key=lambda c: -len(c.name)):
        if cat.name in enr.title:
            return cat.id, cat.name
    return None, None


def session_attendance_status(
    db: Session, *, enrollment_id: int, student_id: int, session_date: date
) -> str:
    """[F008][S002] Attendance label for one session calendar date."""
    row = (
        db.query(Attendance.id)
        .filter(
            Attendance.course_id == enrollment_id,
            Attendance.student_id == student_id,
            Attendance.session_calendar_date == session_date,
        )
        .first()
    )
    return "已簽到" if row else "未簽到"


def enrollment_interval_on_date(enr: CourseEnrollment, day: date) -> tuple[datetime, datetime] | None:
    """[F008][S002] Scheduled start/end on a specific lesson date."""
    if day not in get_lesson_dates_for_enrollment(enr):
        return None
    start = datetime.combine(day, enr.scheduled_start.time())
    end = datetime.combine(day, enr.scheduled_end.time())
    if end <= start:
        from datetime import timedelta

        end = start + timedelta(hours=1)
    return start, end


def build_coach_session_rows(
    db: Session,
    enrollments: list[CourseEnrollment],
    *,
    coach_id: int,
    day: date | None = None,
    from_date: date | None = None,
    to_date: date | None = None,
    category_ids: list[int] | None = None,
) -> list[dict]:
    """[F008][S002] Flatten enrollments into session rows for API and export."""
    filter_cats = set(category_ids) if category_ids else None
    skill_ids = set(coach_skill_category_ids(db, coach_id))
    rows: list[dict] = []

    for enr in enrollments:
        cat_id, cat_name = resolve_enrollment_category(db, enr, skill_ids=skill_ids)
        if cat_id is None or not cat_name:
            continue
        if filter_cats is not None and cat_id not in filter_cats:
            continue

        student = enr.student
        branch = enr.branch
        lesson_dates = get_lesson_dates_for_enrollment(enr)
        try:
            total_lessons = max(1, min(30, int(enr.total_lessons)))
        except (TypeError, ValueError):
            total_lessons = max(1, len(lesson_dates))

        for session_date in lesson_dates:
            if day is not None and session_date != day:
                continue
            if from_date is not None and to_date is not None:
                if session_date < from_date or session_date > to_date:
                    continue

            interval = enrollment_interval_on_date(enr, session_date)
            if interval is None:
                continue
            start_dt, end_dt = interval
            lesson_no = lesson_dates.index(session_date) + 1 if session_date in lesson_dates else None

            rows.append(
                {
                    "enrollment_id": enr.id,
                    "student_id": student.id,
                    "student_name": student.full_name,
                    "student_phone": student.phone,
                    "category_id": cat_id,
                    "category_name": cat_name,
                    "session_date": session_date.isoformat(),
                    "start_time": start_dt.strftime("%H:%M"),
                    "end_time": end_dt.strftime("%H:%M"),
                    "branch_name": branch.name if branch else "—",
                    "branch_id": branch.id if branch else None,
                    "checkin_pin": enr.checkin_pin,
                    "coach_time_confirmed": bool(enr.coach_time_confirmed),
                    "attendance_status": session_attendance_status(
                        db,
                        enrollment_id=enr.id,
                        student_id=student.id,
                        session_date=session_date,
                    ),
                    "course_title": enr.title,
                    "lesson_no": lesson_no,
                    "total_lessons": total_lessons,
                }
            )

    rows.sort(key=lambda r: (r["session_date"], r["start_time"], r["student_name"]))
    return rows


def build_coach_attendance_report_rows(session_rows: list[dict]) -> list[dict]:
    """[F008][S004] Group sessions by course type → students + 上堂日期 (comma-separated)."""
    groups: dict[str, dict[str, set[str]]] = {}
    order: list[str] = []
    for row in session_rows:
        course_type = str(row.get("category_name") or "").strip()
        if not course_type or course_type == "—":
            continue
        student = str(row.get("student_name") or "").strip()
        session_date = str(row.get("session_date") or "").strip()
        if course_type not in groups:
            groups[course_type] = {"students": set(), "dates": set()}
            order.append(course_type)
        if student:
            groups[course_type]["students"].add(student)
        if session_date:
            groups[course_type]["dates"].add(session_date)

    report: list[dict] = []
    for course_type in order:
        bucket = groups[course_type]
        report.append(
            {
                "course_type": course_type,
                "students": ", ".join(sorted(bucket["students"])),
                "session_dates": ", ".join(sorted(bucket["dates"])),
            }
        )
    report.sort(key=lambda r: r["course_type"])
    return report


def _parse_hhmm(value: str) -> tuple[int, int]:
    parts = str(value or "00:00").split(":")
    h = int(parts[0]) if parts and parts[0].isdigit() else 0
    m = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return h, m


def _format_hkt_time(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    local = utc_to_hk(dt)
    return local.strftime("%H:%M")


def _session_duration_hours(start_time: str, end_time: str) -> float:
    sh, sm = _parse_hhmm(start_time)
    eh, em = _parse_hhmm(end_time)
    start_m = sh * 60 + sm
    end_m = eh * 60 + em
    if end_m <= start_m:
        end_m += 24 * 60
    return round(max(0, end_m - start_m) / 60, 1)


def _attendance_for_session(
    db: Session, *, enrollment_id: int, student_id: int, session_date: date
) -> Attendance | None:
    return (
        db.query(Attendance)
        .filter(
            Attendance.course_id == enrollment_id,
            Attendance.student_id == student_id,
            Attendance.session_calendar_date == session_date,
        )
        .first()
    )


def _derive_ledger_status(
    *,
    attended: bool,
    attended_at: datetime | None,
    session_date: date,
    start_time: str,
    today: date,
) -> str:
    """[F008][S005] normal | late | absent | upcoming"""
    if not attended:
        return "upcoming" if session_date > today else "absent"
    if attended_at is None:
        return "normal"
    sh, sm = _parse_hhmm(start_time)
    scheduled = datetime.combine(session_date, time(sh, sm))
    actual = utc_to_hk(attended_at)
    actual_local = datetime.combine(session_date, actual.time())
    if actual_local > scheduled + timedelta(minutes=5):
        return "late"
    return "normal"


def build_coach_attendance_ledger_rows(
    db: Session,
    session_rows: list[dict],
    *,
    coach_id: int,
    coach_name: str,
    coach_username: str | None,
) -> list[dict]:
    """[F008][S005] Flat ledger rows: branch, coach, times, status, remarks."""
    today = now_hk().date()
    ledger: list[dict] = []
    for row in session_rows:
        session_date = date.fromisoformat(str(row["session_date"]))
        att = _attendance_for_session(
            db,
            enrollment_id=int(row["enrollment_id"]),
            student_id=int(row["student_id"]),
            session_date=session_date,
        )
        attended = att is not None or str(row.get("attendance_status")) == "已簽到"
        status = _derive_ledger_status(
            attended=attended,
            attended_at=att.attended_at if att else None,
            session_date=session_date,
            start_time=str(row.get("start_time") or "00:00"),
            today=today,
        )
        check_in = _format_hkt_time(att.attended_at if att else None) or "--:--"
        check_out = _format_hkt_time(att.checked_out_at if att else None) or "--:--"
        hours = _session_duration_hours(str(row.get("start_time") or ""), str(row.get("end_time") or ""))
        remarks = (att.remarks or "").strip() if att and att.remarks else ""
        ledger.append(
            {
                "branch_id": row.get("branch_id"),
                "branch_name": str(row.get("branch_name") or "—"),
                "coach_id": coach_id,
                "coach_name": coach_name,
                "coach_username": coach_username,
                "session_date": session_date.isoformat(),
                "check_in_time": check_in,
                "check_out_time": check_out,
                "lessons_hours": f"1堂 · {hours:g}hr",
                "course_type": str(row.get("category_name") or "—"),
                "status": status,
                "remarks": remarks,
            }
        )
    return ledger


def sort_coach_attendance_ledger_rows(
    rows: list[dict], *, sort_by: str, order: str
) -> list[dict]:
    """[F008][S005] Server-side sort for ledger API."""
    key_map = {
        "branch": lambda r: (r.get("branch_name") or "").lower(),
        "coach": lambda r: (r.get("coach_name") or "").lower(),
        "date": lambda r: (r.get("session_date") or "", r.get("check_in_time") or ""),
        "check_in": lambda r: (r.get("session_date") or "", r.get("check_in_time") or ""),
        "status": lambda r: (r.get("status") or "").lower(),
    }
    key_fn = key_map.get(sort_by, key_map["date"])
    reverse = order.lower() == "desc"
    return sorted(rows, key=key_fn, reverse=reverse)
