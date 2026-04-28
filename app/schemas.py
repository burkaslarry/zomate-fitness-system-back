from datetime import date, datetime

from pydantic import BaseModel, Field, model_validator


class StudentOnboardCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=6, max_length=30)
    email: str | None = None
    health_notes: str | None = None
    disclaimer_accepted: bool = True
    # Optional: if omitted, server assigns a random 5-digit PIN (less typing for students).
    pin_code: str | None = Field(default=None, min_length=4, max_length=10)


class TrialPurchaseInput(BaseModel):
    phone: str
    credits: int = Field(default=10, ge=1, le=200)


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


class FaceIdCheckinInput(BaseModel):
    face_id_external: str


class StudentOut(BaseModel):
    id: int
    full_name: str
    phone: str
    email: str | None
    health_notes: str | None = None
    disclaimer_accepted: bool = False
    pin_code: str = "1234"
    lesson_balance: int
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


class BranchOut(BaseModel):
    id: int
    name: str
    address: str
    code: str
    created_at: datetime

    class Config:
        from_attributes = True


class BranchCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    address: str = Field(min_length=1, max_length=255)
    code: str = Field(min_length=1, max_length=32)


class CoachOut(BaseModel):
    id: int
    full_name: str
    phone: str
    branch_id: int | None
    created_at: datetime

    class Config:
        from_attributes = True


class CoachCreate(BaseModel):
    full_name: str = Field(min_length=1, max_length=120)
    phone: str = Field(min_length=6, max_length=30)
    branch_id: int | None = None


class CourseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    branch_id: int
    coach_id: int
    scheduled_start: datetime
    scheduled_end: datetime
    student_ids: list[int] = Field(default_factory=list)
    credits_on_enroll: int = Field(default=10, ge=0, le=200)
    # Calendar start for the series — defaults to scheduled_start.date() if omitted.
    course_start_date: date | None = None
    lesson_weekdays: list[int] = Field(default_factory=lambda: [0])
    total_lessons: int = Field(default=1, ge=1, le=10)

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


class CourseReschedule(BaseModel):
    scheduled_start: datetime
    scheduled_end: datetime


class CourseEnrollmentOut(BaseModel):
    student_id: int
    student_name: str
    student_phone: str
    checkin_pin: str

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
    enrollments: list[CourseEnrollmentOut] = Field(default_factory=list)
