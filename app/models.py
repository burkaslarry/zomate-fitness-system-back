"""
SQLAlchemy ORM models — table names prefixed ``zomate_fs_*`` (PostgreSQL).

Aligned with product requirements F01–F04: students, branches, coaches,
courses, check-ins, audits, soft-delete ledger via ``DeletedRecord``.
"""

from datetime import datetime, date

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy import Date as DateColumn
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Branch(Base):
    __tablename__ = "zomate_fs_branches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    address: Mapped[str] = mapped_column(String(255), nullable=False)
    code: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    business_start_time: Mapped[str] = mapped_column(String(5), nullable=False, default="09:00")
    business_end_time: Mapped[str] = mapped_column(String(5), nullable=False, default="22:00")
    remarks: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    coaches: Mapped[list["Coach"]] = relationship(back_populates="branch")
    courses: Mapped[list["Course"]] = relationship(back_populates="branch")


class Coach(Base):
    __tablename__ = "zomate_fs_coaches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone: Mapped[str] = mapped_column(String(30), nullable=False, unique=True, index=True)
    branch_id: Mapped[int | None] = mapped_column(
        ForeignKey("zomate_fs_branches.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    branch: Mapped["Branch | None"] = relationship(back_populates="coaches")
    courses: Mapped[list["Course"]] = relationship(back_populates="coach")


class Course(Base):
    __tablename__ = "zomate_fs_courses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    branch_id: Mapped[int] = mapped_column(ForeignKey("zomate_fs_branches.id"), nullable=False)
    coach_id: Mapped[int] = mapped_column(ForeignKey("zomate_fs_coaches.id"), nullable=False)
    scheduled_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    scheduled_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    # Course set: 1–10 lessons, up to 3 weekdays (0=Mon … 6=Sun), comma-separated in DB.
    total_lessons: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    lesson_weekdays: Mapped[str] = mapped_column(String(32), nullable=False, default="0")
    series_start_date: Mapped[date | None] = mapped_column(DateColumn, nullable=True)
    series_end_date: Mapped[date | None] = mapped_column(DateColumn, nullable=True)

    branch: Mapped["Branch"] = relationship(back_populates="courses")
    coach: Mapped["Coach"] = relationship(back_populates="courses")
    enrollments: Mapped[list["CourseEnrollment"]] = relationship(
        back_populates="course", cascade="all, delete-orphan"
    )


class CourseEnrollment(Base):
    __tablename__ = "zomate_fs_course_enrollments"
    __table_args__ = (
        UniqueConstraint("course_id", "student_id", name="uq_zomate_fs_enrollment_course_student"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    course_id: Mapped[int] = mapped_column(ForeignKey("zomate_fs_courses.id"), nullable=False)
    student_id: Mapped[int] = mapped_column(ForeignKey("zomate_fs_students.id"), nullable=False)
    checkin_pin: Mapped[str] = mapped_column(String(5), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    course: Mapped["Course"] = relationship(back_populates="enrollments")
    student: Mapped["Student"] = relationship(back_populates="course_enrollments")


class Student(Base):
    __tablename__ = "zomate_fs_students"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone: Mapped[str] = mapped_column(String(30), nullable=False, unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(120), nullable=True)
    health_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    disclaimer_accepted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pin_code: Mapped[str] = mapped_column(String(10), nullable=False, default="1234")
    face_id_external: Mapped[str | None] = mapped_column(String(80), nullable=True, unique=True)
    lesson_balance: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    checkins: Mapped[list["CheckinLog"]] = relationship(back_populates="student")
    whatsapp_logs: Mapped[list["WhatsAppLog"]] = relationship(back_populates="student")
    course_enrollments: Mapped[list["CourseEnrollment"]] = relationship(
        back_populates="student"
    )
    renewal_records: Mapped[list["RenewalRecord"]] = relationship(back_populates="student")


class RenewalRecord(Base):
    __tablename__ = "zomate_fs_renewal_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    student_id: Mapped[int] = mapped_column(ForeignKey("zomate_fs_students.id"), nullable=False, index=True)
    student_name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    course_ratio: Mapped[str] = mapped_column(String(8), nullable=False)
    lessons: Mapped[int] = mapped_column(Integer, nullable=False)
    payment_method: Mapped[str] = mapped_column(String(80), nullable=False)
    coach_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    remarks: Mapped[str | None] = mapped_column(Text, nullable=True)
    applicant_name: Mapped[str] = mapped_column(String(120), nullable=False)
    signature: Mapped[str] = mapped_column(String(120), nullable=False)
    renewal_date: Mapped[date] = mapped_column(DateColumn, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    student: Mapped["Student"] = relationship(back_populates="renewal_records")


class CheckinLog(Base):
    __tablename__ = "zomate_fs_checkin_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    student_id: Mapped[int] = mapped_column(ForeignKey("zomate_fs_students.id"), nullable=False)
    channel: Mapped[str] = mapped_column(String(30), nullable=False, default="qr_pin")
    remarks: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    student: Mapped["Student"] = relationship(back_populates="checkins")


class WhatsAppLog(Base):
    __tablename__ = "zomate_fs_whatsapp_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    student_id: Mapped[int] = mapped_column(ForeignKey("zomate_fs_students.id"), nullable=False)
    recipient: Mapped[str] = mapped_column(String(120), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    student: Mapped["Student"] = relationship(back_populates="whatsapp_logs")


class AuditLog(Base):
    __tablename__ = "zomate_fs_audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    student_id: Mapped[int] = mapped_column(ForeignKey("zomate_fs_students.id"), nullable=False)
    course_id: Mapped[int | None] = mapped_column(ForeignKey("zomate_fs_courses.id"), nullable=True)
    coach_id: Mapped[int | None] = mapped_column(ForeignKey("zomate_fs_coaches.id"), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class DeletedRecord(Base):
    __tablename__ = "zomate_fs_deleted_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    deleted_by_username: Mapped[str | None] = mapped_column(String(120), nullable=True)
    deleted_hard: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    class Config:
        unique_together = ("entity_type", "entity_id")


class AppUser(Base):
    __tablename__ = "zomate_fs_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    role: Mapped[str] = mapped_column(String(24), nullable=False)
    password_salt: Mapped[str] = mapped_column(String(80), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuthSession(Base):
    __tablename__ = "zomate_fs_auth_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    token: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("zomate_fs_users.id"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped["AppUser"] = relationship()
