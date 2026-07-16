"""[F008][S002]
Feature: Coach Session Management
Step: Filtered session query and export helpers
Logic: Expand enrollments into per-session rows with category resolution and attendance.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy.orm import Session, joinedload

from .enrollment_schedule import get_lesson_dates_for_enrollment
from .models import Attendance, CategoryEnrollment, CourseCategory, CourseEnrollment


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
        for session_date in get_lesson_dates_for_enrollment(enr):
            if day is not None and session_date != day:
                continue
            if from_date is not None and to_date is not None:
                if session_date < from_date or session_date > to_date:
                    continue

            interval = enrollment_interval_on_date(enr, session_date)
            if interval is None:
                continue
            start_dt, end_dt = interval

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
                    "checkin_pin": enr.checkin_pin,
                    "coach_time_confirmed": bool(enr.coach_time_confirmed),
                    "attendance_status": session_attendance_status(
                        db,
                        enrollment_id=enr.id,
                        student_id=student.id,
                        session_date=session_date,
                    ),
                    "course_title": enr.title,
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
