"""[F007][S002]
Feature: Backend platform (FastAPI & PostgreSQL)
Step: (see Logic)
Logic: Pydantic request and response models for HTTP routes.
"""

from datetime import date, datetime

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class StudentOnboardCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=6, max_length=30)
    email: str | None = None
    date_of_birth: date
    health_notes: str | None = None
    disclaimer_accepted: bool = True


class TrialPurchaseInput(BaseModel):
    phone: str
    credits: int = Field(default=10, ge=1, le=200)


class ParqQuestionsIn(BaseModel):
    """Frontend PAR-Q checklist — aligns with ``lib/schemas/student.ts``."""

    q1_heart_condition: bool = False
    q2_chest_pain_activity: bool = False
    q3_chest_pain_rest: bool = False
    q4_dizziness: bool = False
    q5_bone_joint_problem: bool = False
    q6_blood_pressure_meds: bool = False
    q7_other_reason: bool = False

    def any_yes(self) -> bool:
        return any(self.model_dump().values())


class StudentRegisterV1(BaseModel):
    """``POST /api/v1/students/register`` — F01 wizard body (Zod mirror)."""

    full_name: str = Field(min_length=1, max_length=120)
    hkid: str = Field(min_length=4, max_length=32)
    phone: str = Field(min_length=8, max_length=30)
    email: str | None = None
    date_of_birth: date
    emergency_contact_name: str = Field(min_length=1, max_length=120)
    emergency_contact_phone: str = Field(min_length=8, max_length=30)
    form_type: Literal["new", "renewal"]
    parq: ParqQuestionsIn
    medical_clearance_file_name: str | None = ""
    cooling_off_acknowledged: bool = True
    disclaimer_accepted: bool = True
    digital_signature: str = Field(min_length=20, max_length=400_000)
    package_sessions: Literal[10, 30]
    renewal_notes: str | None = None

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v: object) -> object:
        if v == "":
            return None
        return v

    @model_validator(mode="after")
    def validate_ack_and_clearance(self) -> "StudentRegisterV1":
        if not self.cooling_off_acknowledged or not self.disclaimer_accepted:
            raise ValueError("請確認冷靜期條款及免責聲明。")
        return self


class MemberProspectDupCheck(BaseModel):
    """F01 步驟 1 — 未登記前預檢姓名／HKID／電話是否已有會員紀錄（無須 Bearer）。"""

    full_name: str = Field(min_length=1, max_length=120)
    hkid: str = Field(min_length=4, max_length=32)
    phone: str = Field(min_length=3, max_length=36)


class RenewalCreate(BaseModel):
    """續會須對應已存在學員（以 admin / student-search 揀選後帶 student_id）。"""
    student_id: int = Field(ge=1)
    full_name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=6, max_length=30)
    course_ratio: Literal["1:1", "1:2"]
    lessons: Literal[10, 30]
    payment_method: str = Field(min_length=1, max_length=80)
    coach_name: str | None = Field(default=None, max_length=120)
    remarks: str | None = None
    applicant_name: str = Field(min_length=1, max_length=120)
    signature: str = Field(min_length=1, max_length=120)
    renewal_date: date


class MemberCreate(BaseModel):
    chinese_name: str = Field(min_length=1, max_length=120)
    full_name: str = Field(min_length=1, max_length=120)
    nickname: str | None = Field(default=None, max_length=80)
    gender: Literal["male", "female"]
    hkid: str = Field(min_length=4, max_length=32)
    phone: str = Field(min_length=8, max_length=30)
    email: str | None = None
    date_of_birth: date
    emergency_contact_name: str = Field(min_length=1, max_length=120)
    emergency_contact_relationship: str = Field(min_length=1, max_length=80)
    emergency_contact_phone: str = Field(min_length=8, max_length=30)
    parq: ParqQuestionsIn
    medical_clearance_file_name: str | None = ""
    pdpo_acknowledged: bool = True
    cooling_off_acknowledged: bool = True
    disclaimer_accepted: bool = True
    digital_signature: str = Field(min_length=20, max_length=400_000)
    coach_id: int | None = Field(default=None, ge=1)
    coach_username: str | None = Field(default=None, min_length=1, max_length=120)
    course_category_id: int | None = Field(default=None, ge=1)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, v: object) -> object:
        if v == "":
            return None
        return v

    @model_validator(mode="after")
    def validate_ack_and_clearance(self) -> "MemberCreate":
        if not self.pdpo_acknowledged or not self.cooling_off_acknowledged or not self.disclaimer_accepted:
            raise ValueError("請確認收集個人資料聲明、冷靜期條款及免責聲明。")
        return self


class MemberUpdate(BaseModel):
    """[F001][S003] Staff profile edit from admin student detail."""

    full_name: str | None = Field(default=None, min_length=1, max_length=120)
    phone: str | None = Field(default=None, min_length=8, max_length=30)
    email: str | None = None
    date_of_birth: date | None = None
    emergency_contact_name: str | None = Field(default=None, max_length=120)
    emergency_contact_phone: str | None = Field(default=None, max_length=30)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_update_email(cls, v: object) -> object:
        if v == "":
            return None
        return v


class PackageOut(BaseModel):
    id: int
    name: str
    sessions: int
    price: float
    active: bool = True
    created_at: datetime

    class Config:
        from_attributes = True


class CourseCategoryAdminUpdate(BaseModel):
    """[F011][S001] 課堂和分店管理 — 啟用／停用 course category。"""

    is_active: bool | None = None


class TrialClassCreate(BaseModel):
    """試堂／加堂 — 學員請提供其一：`student_phone`（建議）、`member_hkid` 或 `student_id`。"""

    type: Literal["TRIAL", "ADD_ON"]
    course_category_id: int | None = None
    coach_id: int | None = None
    branch_id: int | None = None
    class_date: date
    note: str | None = None
    member_hkid: str | None = Field(default=None, max_length=32)
    student_phone: str | None = Field(default=None, max_length=36)
    student_id: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def exactly_one_student_identity(self) -> "TrialClassCreate":
        hk = (self.member_hkid or "").strip()
        ph = (self.student_phone or "").strip()
        sid = self.student_id
        n = sum([bool(hk), bool(ph), sid is not None])
        if n != 1:
            raise ValueError("請提供其一：student_phone、member_hkid 或 student_id")
        return self


class ExpenseCreate(BaseModel):
    date: date
    category: Literal["rent", "salary", "supplies", "other"]
    amount: float = Field(gt=0)
    note: str | None = None


class CheckinInput(BaseModel):
    """Redeem one lesson: identify by phone XOR student_id, then PIN."""

    pin_code: str = Field(min_length=4, max_length=10)
    phone: str | None = None
    student_id: int | None = None

    @model_validator(mode="after")
    def exactly_one_identity(self) -> "CheckinInput":
        phone_ok = self.phone is not None and str(self.phone).strip() != ""
        sid_ok = self.student_id is not None
        if phone_ok == sid_ok:
            raise ValueError("Provide exactly one of phone or student_id")
        return self


class ManualLessonRedeemInput(BaseModel):
    """Staff-only ledger redeem that intentionally bypasses same-day QR attendance duplicate guards."""

    lessons: int = Field(default=1, ge=1, le=30)
    reason: str = Field(default="admin_manual_redeem", min_length=1, max_length=160)
    remarks: str | None = Field(default=None, max_length=255)


class LedgerAdjustInput(BaseModel):
    """[F007][S002] Admin correction when payment + course open double-credited the ledger."""

    delta_lessons: int = Field(..., ge=-100, le=100)
    reason: str = Field(default="admin_ledger_adjust", min_length=1, max_length=160)
    remarks: str | None = Field(default=None, max_length=255)


class FaceIdCheckinInput(BaseModel):
    face_id_external: str


class StudentOut(BaseModel):
    id: int
    full_name: str
    hkid: str | None = None
    phone: str
    email: str | None
    date_of_birth: date | None = None
    used_mobile_number: str | None = None
    emergency_contact_name: str | None = None
    emergency_contact_phone: str | None = None
    health_notes: str | None = None
    disclaimer_accepted: bool = False
    photo_path: str | None = None
    signature_image_url: str | None = None
    lesson_balance: int = Field(description="由 zomate_fs_lesson_ledger 加總；ORM Student 無此欄。")
    face_id_external: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=64)


class LoginSession(BaseModel):
    token: str
    username: str
    role: str
    access_role: str = "CLERK"
    is_master_admin: bool = False
    permissions: list[str] = Field(default_factory=list)


class AccessRightsMatrixOut(BaseModel):
    rows: list[dict]
    role_labels: dict[str, str]


class SystemUserOut(BaseModel):
    id: int
    username: str
    role: str
    access_role: str
    is_master_admin: bool
    is_active: bool
    coach_id: int | None = None
    permissions: list[str] = Field(default_factory=list)
    uses_custom_permissions: bool = False
    created_at: datetime


class SystemUserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=80)
    password: str = Field(min_length=6, max_length=64)
    role: Literal["CLERK", "COACH", "MASTER_ADMIN"] = "CLERK"
    coach_id: int | None = Field(default=None, ge=1)
    permissions: list[str] | None = None


class SystemUserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=6, max_length=64)
    role: Literal["CLERK", "COACH", "MASTER_ADMIN"] | None = None
    is_active: bool | None = None
    coach_id: int | None = Field(default=None, ge=1)
    permissions: list[str] | None = None
    reset_permissions: bool = False


class BranchOut(BaseModel):
    id: int
    name: str
    address: str
    code: str
    business_start_time: str = "09:00"
    business_end_time: str = "22:00"
    remarks: str | None = None
    active: bool = True
    created_at: datetime

    class Config:
        from_attributes = True


class BranchCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    address: str = Field(min_length=1, max_length=255)
    code: str | None = Field(default=None, max_length=32)
    business_start_time: str = Field(default="09:00", pattern=r"^\d{2}:\d{2}$")
    business_end_time: str = Field(default="22:00", pattern=r"^\d{2}:\d{2}$")
    remarks: str | None = None


class BranchUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    address: str | None = Field(default=None, min_length=1, max_length=255)
    business_start_time: str | None = Field(default=None, pattern=r"^\d{2}:\d{2}$")
    business_end_time: str | None = Field(default=None, pattern=r"^\d{2}:\d{2}$")
    remarks: str | None = None
    active: bool | None = None


class CoachEnrolledStudentOut(BaseModel):
    """學員透過至少一個 ``CourseEnrollment`` 報讀該教練名下課程。"""

    id: int
    full_name: str
    phone: str


class CoachOut(BaseModel):
    id: int
    full_name: str
    phone: str
    specialty: str | None = None
    active: bool = True
    branch_id: int | None
    branch_name: str | None = None
    hire_date: date | None = None
    login_username: str | None = None
    created_at: datetime
    enrolled_students: list[CoachEnrolledStudentOut] = Field(default_factory=list)
    skill_category_ids: list[int] = Field(default_factory=list)

    class Config:
        from_attributes = True


class CoachSkillsUpdate(BaseModel):
    """[F011][S002] Admin assigns course categories a coach may teach."""

    course_category_ids: list[int] = Field(default_factory=list)


class CoachCreate(BaseModel):
    full_name: str = Field(min_length=1, max_length=120)
    phone: str = Field(min_length=6, max_length=30)
    specialty: str | None = Field(default=None, max_length=160)
    branch_id: int | None = None
    hire_date: date | None = Field(default=None, description="入職日期；省略則為伺服器今日（UTC 日期）")
    login_username: str | None = Field(default=None, min_length=3, max_length=120)
    password: str | None = Field(default=None, min_length=6, max_length=64)


class CoachUpdate(BaseModel):
    """Partial update — omit fields you do not want to change."""

    full_name: str | None = Field(default=None, min_length=1, max_length=120)
    phone: str | None = Field(default=None, min_length=6, max_length=30)
    specialty: str | None = Field(default=None, max_length=160)
    active: bool | None = None
    branch_id: int | None = None
    hire_date: date | None = None
    login_username: str | None = Field(default=None, min_length=3, max_length=120)
    password: str | None = Field(default=None, min_length=6, max_length=64)


class CourseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    branch_id: int
    coach_id: int
    scheduled_start: datetime
    scheduled_end: datetime
    student_ids: list[int] = Field(default_factory=list)
    # Calendar start for the series — defaults to scheduled_start.date() if omitted.
    course_start_date: date | None = None
    lesson_weekdays: list[int] = Field(default_factory=lambda: [0])
    total_lessons: int = Field(default=10, ge=10, le=30)
    # >1 → one PIN per installment tranche (serialized on enrollment.segment_pins_json).
    total_installments: int = Field(default=1, ge=1, le=3)
    # Optional HKD split per installment (length must match total_installments when set).
    installment_amounts: list[float] | None = None
    # Optional: staff records a verbally agreed first session time — logged to coach WhatsApp.
    student_first_session_at: datetime | None = None
    coach_schedule_note: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def validate_weekdays(self) -> "CourseCreate":
        u = sorted(set(self.lesson_weekdays))
        if not u:
            raise ValueError("lesson_weekdays must include at least one day (Mon–Sun).")
        if len(u) > 3:
            raise ValueError("At most 3 weekdays may be selected.")
        if any(d < 0 or d > 6 for d in u):
            raise ValueError("weekday must be between 0 (Mon) and 6 (Sun).")
        object.__setattr__(self, "lesson_weekdays", u)
        return self

    @model_validator(mode="after")
    def validate_installments_vs_lessons(self) -> "CourseCreate":
        if self.total_installments > self.total_lessons:
            raise ValueError("total_installments cannot exceed total_lessons.")
        if self.installment_amounts is not None:
            if len(self.installment_amounts) != self.total_installments:
                raise ValueError("installment_amounts length must match total_installments.")
            if any(a <= 0 for a in self.installment_amounts):
                raise ValueError("installment_amounts must be positive.")
        return self


class CourseReschedule(BaseModel):
    scheduled_start: datetime
    scheduled_end: datetime


class CoachScheduleConfirm(BaseModel):
    """[F003][S001] Coach assigns 0.5–2 hour slot on a calendar day for one enrollment."""

    coach_id: int | None = None
    enrollment_id: int = Field(ge=1)
    day: date
    start_hour: int = Field(ge=9, le=18)
    start_minute: int = Field(default=0, ge=0, le=45)
    duration_hours: float = Field(ge=0.5, le=2)

    @model_validator(mode="after")
    def validate_slot_within_business_hours(self) -> "CoachScheduleConfirm":
        allowed = {0.5, 1.0, 1.5, 2.0}
        if self.duration_hours not in allowed:
            raise ValueError("duration_hours must be 0.5, 1, 1.5, or 2.")
        if self.start_minute not in {0, 15, 30, 45}:
            raise ValueError("start_minute must be 0, 15, 30, or 45.")
        if self.start_hour + self.start_minute / 60.0 + self.duration_hours > 19:
            raise ValueError("Time slot must end by 19:00 (7pm).")
        return self


class CoachSignatureUpdate(BaseModel):
    digital_signature: str = Field(min_length=20, max_length=400_000)


class CoachMeOut(BaseModel):
    id: int
    full_name: str
    phone: str
    branch_id: int | None = None
    branch_name: str | None = None


class CoachPendingStudentOut(BaseModel):
    enrollment_id: int
    course_id: int
    student_id: int
    student_name: str
    student_phone: str
    course_title: str
    branch_name: str
    total_lessons: int
    placeholder_start: datetime


class CoachStudentPaymentOut(BaseModel):
    student_id: int
    student_name: str
    student_phone: str
    course_id: int
    course_title: str
    payment_status: str
    installment_status: str
    amount_paid: float | None = None
    amount_total: float | None = None
    next_installment_no: int | None = None
    next_reminder_lesson: int | None = None
    signature_image_url: str | None = None


class CoachStudentBriefOut(BaseModel):
    """[F003][S005] Coach roster — students assigned via course enrollments."""

    student_id: int
    full_name: str
    phone: str
    lesson_balance: int
    enrollment_count: int
    pending_schedule: bool


class CoachStudentEnrollmentOut(BaseModel):
    enrollment_id: int
    course_title: str
    scheduled_start: datetime
    scheduled_end: datetime
    total_lessons: int
    coach_time_confirmed: bool
    payment_status: str
    installment_status: str
    next_installment_no: int | None = None
    next_reminder_lesson: int | None = None


class CoachStudentCheckinOut(BaseModel):
    id: int
    channel: str
    remarks: str | None
    created_at: datetime


class CoachStudentAttendanceOut(BaseModel):
    id: int
    course_id: int | None
    course_title: str | None
    session_calendar_date: date
    attended_at: datetime


class CoachStudentRecordOut(BaseModel):
    """[F003][S005] Full student dossier for coach portal."""

    student_id: int
    full_name: str
    phone: str
    lesson_balance: int
    enrollments: list[CoachStudentEnrollmentOut]
    checkins: list[CoachStudentCheckinOut]
    attendance: list[CoachStudentAttendanceOut]


class CoachRemindPaymentBody(BaseModel):
    """[F003][S006] Coach-triggered installment / balance payment reminder."""

    course_id: int = Field(ge=1)
    coach_id: int | None = None


class CoachRemindPaymentOut(BaseModel):
    ok: bool
    message: str
    wa_link: str
    logged: bool


class CoachStudentFollowUpOut(BaseModel):
    """[F003][S008] Admin coach student follow-up grid row."""

    student_id: int
    full_name: str
    phone: str
    courses: str
    attendance_status: str
    next_lesson: str
    payment_reminder: str | None = None


class CoachBookSession(BaseModel):
    """[F003][S007] Coach books or reschedules 0.5–2h session; server rejects slot conflicts."""

    coach_id: int | None = None
    enrollment_id: int = Field(ge=1)
    day: date
    start_hour: int = Field(ge=9, le=18)
    start_minute: int = Field(default=0, ge=0, le=45)
    duration_hours: float = Field(ge=0.5, le=2)

    @model_validator(mode="after")
    def validate_slot_within_business_hours(self) -> "CoachBookSession":
        allowed = {0.5, 1.0, 1.5, 2.0}
        if self.duration_hours not in allowed:
            raise ValueError("duration_hours must be 0.5, 1, 1.5, or 2.")
        if self.start_minute not in {0, 15, 30, 45}:
            raise ValueError("start_minute must be 0, 15, 30, or 45.")
        if self.start_hour + self.start_minute / 60.0 + self.duration_hours > 19:
            raise ValueError("Time slot must end by 19:00 (7pm).")
        return self


class CourseAssignCoach(BaseModel):
    """Reassign a course series to another coach (staff)."""

    coach_id: int = Field(ge=1)


class InstallmentSegmentPinOut(BaseModel):
    installment_no: int = Field(ge=1)
    lesson_from: int = Field(ge=1)
    lesson_to: int = Field(ge=1)
    pin: str = Field(min_length=1, max_length=8)
    paid: bool = True
    reminder_lesson: int | None = Field(default=None, ge=1)
    amount_hkd: float | None = Field(default=None, ge=0)


class CourseInstallmentMarkPaid(BaseModel):
    """Staff marks one scheduled-package installment segment as collected — unlocks that tranche PIN for check-in."""

    student_id: int = Field(ge=1)
    installment_no: int = Field(ge=1, le=3)


class CourseInstallmentReminderUpdate(BaseModel):
    """[F003][S003] Staff adjusts the lesson number that triggers a WhatsApp installment reminder."""

    student_id: int = Field(ge=1)
    installment_no: int = Field(ge=1, le=3)
    reminder_lesson: int = Field(ge=1, le=999)


class CourseEnrollmentOut(BaseModel):
    student_id: int
    student_name: str
    student_phone: str
    checkin_pin: str
    installment_segments: list[InstallmentSegmentPinOut] = Field(default_factory=list)

    class Config:
        from_attributes = True


class CourseOut(BaseModel):
    id: int
    title: str
    branch_id: int
    branch_name: str
    branch_address: str
    coach_id: int
    coach_name: str
    scheduled_start: datetime
    scheduled_end: datetime
    created_at: datetime
    total_lessons: int = 1
    lesson_weekdays: list[int] = Field(default_factory=lambda: [0])
    series_start_date: date | None = None
    series_end_date: date | None = None
    coach_time_confirmed: bool = True
    enrollments: list[CourseEnrollmentOut] = Field(default_factory=list)


class CoachEnrollmentCancelBody(BaseModel):
    """[F003][S009] Coach soft-cancels an assigned enrollment."""

    coach_id: int | None = None


class CoachSessionOut(BaseModel):
    """[F008][S002] One coach session row (student + date + category)."""

    enrollment_id: int
    student_id: int
    student_name: str
    student_phone: str
    category_id: int | None = None
    category_name: str
    session_date: str
    start_time: str
    end_time: str
    branch_name: str
    checkin_pin: str
    coach_time_confirmed: bool
    attendance_status: str
    course_title: str


class CoachAttendanceReportRowOut(BaseModel):
    """[F008][S004] Monthly coach attendance rollup by course type."""

    course_type: str
    students: str
    session_dates: str


class CoachAttendanceReportOut(BaseModel):
    """[F008][S004] Month-scoped coach attendance dashboard payload."""

    month: str
    from_date: date
    to_date: date
    rows: list[CoachAttendanceReportRowOut] = Field(default_factory=list)


class CourseCategoryCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)


class StudentCategoryEnrollmentCreate(BaseModel):
    course_category_id: int
    total_lessons: int = Field(ge=10, le=999)
    total_installments: int = Field(default=3, ge=1, le=3)


class CoachTrialGrantBody(BaseModel):
    coach_id: int | None = None
    branch_id: int | None = None
    class_date: date | None = None


class WhatsAppTemplateOut(BaseModel):
    """[F005][S003] Admin WhatsApp template row."""

    key: str
    audience: str
    title: str
    body: str
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class WhatsAppTemplateUpdate(BaseModel):
    """[F005][S003] Update template body (placeholders preserved)."""

    body: str = Field(min_length=1)


class PaymentNotificationSendBody(BaseModel):
    """[F005][S003] Staff triggers payment reminder WhatsApp logs for student + coach."""

    course_enrollment_id: int | None = Field(default=None, ge=1)
    installment_no: int | None = Field(default=None, ge=1, le=3)
    installment_plan_id: int | None = Field(default=None, ge=1)
    receipt_confirmed: bool = True
    notify_coach: bool = True
    amount: float | None = Field(default=None, ge=0)


class WhatsAppStatusOut(BaseModel):
    """[F005][S003] WhatsApp Business API configuration snapshot (no secrets)."""

    enabled: bool
    configured: bool
    phone_number_id_set: bool
    access_token_set: bool
    business_account_id_set: bool
    app_id_set: bool
    default_language: str
    template_map_keys: list[str]


class WhatsAppTestSendBody(BaseModel):
    """[F005][S003] Admin test send using a Meta-approved template name."""

    phone: str = Field(min_length=8, max_length=30)
    template_name: str = Field(min_length=1, max_length=128)
    language_code: str = Field(default="zh_HK", min_length=2, max_length=16)
    body_parameters: list[str] = Field(default_factory=list)
