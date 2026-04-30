"""management tables and member uploads

Revision ID: 20260430_0001
Revises:
Create Date: 2026-04-30
"""

from alembic import op

revision = "20260430_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_branches (
            id SERIAL PRIMARY KEY,
            name VARCHAR(160) NOT NULL,
            address VARCHAR(255) NOT NULL,
            code VARCHAR(32) NOT NULL UNIQUE,
            business_start_time VARCHAR(5) NOT NULL DEFAULT '09:00',
            business_end_time VARCHAR(5) NOT NULL DEFAULT '22:00',
            remarks TEXT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_coaches (
            id SERIAL PRIMARY KEY,
            full_name VARCHAR(120) NOT NULL,
            phone VARCHAR(30) NOT NULL UNIQUE,
            branch_id INTEGER NULL REFERENCES zomate_fs_branches(id),
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_students (
            id SERIAL PRIMARY KEY,
            full_name VARCHAR(120) NOT NULL,
            phone VARCHAR(30) NOT NULL UNIQUE,
            email VARCHAR(120) NULL,
            health_notes TEXT NULL,
            disclaimer_accepted BOOLEAN NOT NULL DEFAULT FALSE,
            pin_code VARCHAR(10) NOT NULL DEFAULT '1234',
            face_id_external VARCHAR(80) NULL UNIQUE,
            lesson_balance INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_courses (
            id SERIAL PRIMARY KEY,
            title VARCHAR(200) NOT NULL,
            branch_id INTEGER NOT NULL REFERENCES zomate_fs_branches(id),
            coach_id INTEGER NOT NULL REFERENCES zomate_fs_coaches(id),
            scheduled_start TIMESTAMP NOT NULL,
            scheduled_end TIMESTAMP NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            total_lessons INTEGER NOT NULL DEFAULT 1,
            lesson_weekdays VARCHAR(32) NOT NULL DEFAULT '0',
            series_start_date DATE NULL,
            series_end_date DATE NULL
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_course_enrollments (
            id SERIAL PRIMARY KEY,
            course_id INTEGER NOT NULL REFERENCES zomate_fs_courses(id),
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            checkin_pin VARCHAR(5) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_zomate_fs_enrollment_course_student UNIQUE (course_id, student_id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_renewal_records (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            student_name VARCHAR(120) NOT NULL,
            phone VARCHAR(30) NOT NULL,
            course_ratio VARCHAR(8) NOT NULL,
            lessons INTEGER NOT NULL,
            payment_method VARCHAR(80) NOT NULL,
            coach_name VARCHAR(120) NULL,
            remarks TEXT NULL,
            applicant_name VARCHAR(120) NOT NULL,
            signature VARCHAR(120) NOT NULL,
            renewal_date DATE NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_checkin_logs (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            channel VARCHAR(30) NOT NULL DEFAULT 'qr_pin',
            remarks VARCHAR(255) NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_whatsapp_logs (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            recipient VARCHAR(120) NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_audit_logs (
            id SERIAL PRIMARY KEY,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            action VARCHAR(48) NOT NULL,
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            course_id INTEGER NULL REFERENCES zomate_fs_courses(id),
            coach_id INTEGER NULL REFERENCES zomate_fs_coaches(id),
            detail TEXT NULL
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_deleted_records (
            id SERIAL PRIMARY KEY,
            entity_type VARCHAR(32) NOT NULL,
            entity_id INTEGER NOT NULL,
            deleted_by_username VARCHAR(120) NULL,
            deleted_hard BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(120) NOT NULL UNIQUE,
            role VARCHAR(24) NOT NULL,
            password_salt VARCHAR(80) NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_auth_sessions (
            id SERIAL PRIMARY KEY,
            token VARCHAR(128) NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES zomate_fs_users(id),
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )

    op.execute("ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS hkid VARCHAR(32) NULL")
    op.execute("ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS emergency_contact_name VARCHAR(120) NULL")
    op.execute("ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS emergency_contact_phone VARCHAR(30) NULL")
    op.execute("ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS photo_path VARCHAR(512) NULL")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_zomate_fs_students_hkid ON zomate_fs_students (hkid)")

    op.execute("ALTER TABLE zomate_fs_branches ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE")
    op.execute("ALTER TABLE zomate_fs_coaches ADD COLUMN IF NOT EXISTS specialty VARCHAR(160) NULL")
    op.execute("ALTER TABLE zomate_fs_coaches ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_packages (
            id SERIAL PRIMARY KEY,
            name VARCHAR(160) NOT NULL,
            sessions INTEGER NOT NULL,
            price NUMERIC(12,2) NOT NULL DEFAULT 0,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_packages_id ON zomate_fs_packages (id)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_student_photos (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            member_hkid VARCHAR(32) NOT NULL,
            file_path VARCHAR(512) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_student_photos_member_hkid ON zomate_fs_student_photos (member_hkid)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_student_photos_created_at ON zomate_fs_student_photos (created_at)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_receipts (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            member_hkid VARCHAR(32) NOT NULL,
            file_path VARCHAR(512) NOT NULL,
            amount NUMERIC(12,2) NULL,
            payment_method VARCHAR(80) NULL,
            note TEXT NULL,
            source VARCHAR(24) NOT NULL DEFAULT 'REGISTER',
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_receipts_member_hkid ON zomate_fs_receipts (member_hkid)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_receipts_created_at ON zomate_fs_receipts (created_at)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_trial_classes (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            member_hkid VARCHAR(32) NOT NULL,
            type VARCHAR(16) NOT NULL,
            coach_id INTEGER NULL REFERENCES zomate_fs_coaches(id),
            branch_id INTEGER NULL REFERENCES zomate_fs_branches(id),
            class_date DATE NOT NULL,
            note TEXT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_trial_classes_member_hkid ON zomate_fs_trial_classes (member_hkid)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_trial_classes_created_at ON zomate_fs_trial_classes (created_at)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_expenses (
            id SERIAL PRIMARY KEY,
            date DATE NOT NULL,
            category VARCHAR(80) NOT NULL,
            amount NUMERIC(12,2) NOT NULL,
            note TEXT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_expenses_date ON zomate_fs_expenses (date)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_expenses_created_at ON zomate_fs_expenses (created_at)")

    op.execute("ALTER TABLE zomate_fs_renewal_records ADD COLUMN IF NOT EXISTS package_id INTEGER NULL REFERENCES zomate_fs_packages(id)")
    op.execute("ALTER TABLE zomate_fs_renewal_records ADD COLUMN IF NOT EXISTS coach_id INTEGER NULL REFERENCES zomate_fs_coaches(id)")
    op.execute("ALTER TABLE zomate_fs_renewal_records ADD COLUMN IF NOT EXISTS branch_id INTEGER NULL REFERENCES zomate_fs_branches(id)")
    op.execute("ALTER TABLE zomate_fs_renewal_records ADD COLUMN IF NOT EXISTS amount NUMERIC(12,2) NULL")
    op.execute("ALTER TABLE zomate_fs_renewal_records ADD COLUMN IF NOT EXISTS receipt_id INTEGER NULL REFERENCES zomate_fs_receipts(id)")


def downgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_renewal_records DROP COLUMN IF EXISTS receipt_id")
    op.execute("ALTER TABLE zomate_fs_renewal_records DROP COLUMN IF EXISTS amount")
    op.execute("ALTER TABLE zomate_fs_renewal_records DROP COLUMN IF EXISTS branch_id")
    op.execute("ALTER TABLE zomate_fs_renewal_records DROP COLUMN IF EXISTS coach_id")
    op.execute("ALTER TABLE zomate_fs_renewal_records DROP COLUMN IF EXISTS package_id")
    op.execute("DROP TABLE IF EXISTS zomate_fs_expenses")
    op.execute("DROP TABLE IF EXISTS zomate_fs_trial_classes")
    op.execute("DROP TABLE IF EXISTS zomate_fs_receipts")
    op.execute("DROP TABLE IF EXISTS zomate_fs_student_photos")
    op.execute("DROP TABLE IF EXISTS zomate_fs_packages")
    op.execute("ALTER TABLE zomate_fs_coaches DROP COLUMN IF EXISTS active")
    op.execute("ALTER TABLE zomate_fs_coaches DROP COLUMN IF EXISTS specialty")
    op.execute("ALTER TABLE zomate_fs_branches DROP COLUMN IF EXISTS active")
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS photo_path")
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS emergency_contact_phone")
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS emergency_contact_name")
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS hkid")
