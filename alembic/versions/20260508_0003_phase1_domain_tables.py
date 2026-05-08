"""Phase-1 domain: categories, category enrollments, installments, ledger, attendance.

Revision ID: 20260508_0003
Revises: 20260430_0002
Create Date: 2026-05-08
"""

from alembic import op

revision = "20260508_0003"
down_revision = "20260430_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS pin_hash VARCHAR(128) NULL")
    op.execute("ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS hkid_prefix4 VARCHAR(4) NULL")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_course_categories (
            id SERIAL PRIMARY KEY,
            name VARCHAR(160) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_by_role VARCHAR(24) NOT NULL DEFAULT 'admin',
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_course_categories_active ON zomate_fs_course_categories (is_active)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_category_enrollments (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            course_category_id INTEGER NOT NULL REFERENCES zomate_fs_course_categories(id),
            status VARCHAR(32) NOT NULL DEFAULT 'active',
            started_at DATE NOT NULL DEFAULT CURRENT_DATE,
            total_lessons INTEGER NOT NULL DEFAULT 0,
            notes TEXT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_zomate_fs_cat_enrollment_student_category UNIQUE (student_id, course_category_id)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_zomate_fs_cat_enrollment_student ON zomate_fs_category_enrollments (student_id)"
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_installment_plans (
            id SERIAL PRIMARY KEY,
            enrollment_id INTEGER NOT NULL REFERENCES zomate_fs_category_enrollments(id) ON DELETE CASCADE,
            total_installments INTEGER NOT NULL DEFAULT 3,
            status VARCHAR(32) NOT NULL DEFAULT 'active',
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT ck_zomate_fs_installments_count CHECK (total_installments >= 1 AND total_installments <= 5)
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_installment_payments (
            id SERIAL PRIMARY KEY,
            installment_plan_id INTEGER NOT NULL REFERENCES zomate_fs_installment_plans(id) ON DELETE CASCADE,
            installment_no INTEGER NOT NULL,
            amount NUMERIC(12, 2) NOT NULL DEFAULT 0,
            due_date DATE NOT NULL,
            paid_at TIMESTAMP NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_zomate_fs_installment_no UNIQUE (installment_plan_id, installment_no)
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_lesson_ledger (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            enrollment_id INTEGER NULL REFERENCES zomate_fs_category_enrollments(id) ON DELETE SET NULL,
            delta_lessons INTEGER NOT NULL,
            reason VARCHAR(160) NOT NULL,
            created_by_role VARCHAR(24) NOT NULL DEFAULT 'system',
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_lesson_ledger_student ON zomate_fs_lesson_ledger (student_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_lesson_ledger_created ON zomate_fs_lesson_ledger (created_at)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_attendance (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            enrollment_id INTEGER NULL REFERENCES zomate_fs_category_enrollments(id) ON DELETE SET NULL,
            coach_id INTEGER NULL REFERENCES zomate_fs_coaches(id),
            branch_id INTEGER NULL REFERENCES zomate_fs_branches(id),
            course_id INTEGER NULL REFERENCES zomate_fs_courses(id) ON DELETE SET NULL,
            attended_at TIMESTAMP NOT NULL DEFAULT NOW(),
            session_calendar_date DATE NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_zomate_fs_attendance_student_course_day
        ON zomate_fs_attendance (student_id, course_id, session_calendar_date)
        WHERE course_id IS NOT NULL
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_attendance_student_date ON zomate_fs_attendance (student_id, session_calendar_date)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_zomate_fs_attendance_student_date")
    op.execute("DROP INDEX IF EXISTS uq_zomate_fs_attendance_student_course_day")
    op.execute("DROP TABLE IF EXISTS zomate_fs_attendance")
    op.execute("DROP TABLE IF EXISTS zomate_fs_lesson_ledger")
    op.execute("DROP TABLE IF EXISTS zomate_fs_installment_payments")
    op.execute("DROP TABLE IF EXISTS zomate_fs_installment_plans")
    op.execute("DROP TABLE IF EXISTS zomate_fs_category_enrollments")
    op.execute("DROP TABLE IF EXISTS zomate_fs_course_categories")
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS hkid_prefix4")
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS pin_hash")
