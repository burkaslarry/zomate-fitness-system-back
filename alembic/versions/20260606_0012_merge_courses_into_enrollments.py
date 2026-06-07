"""[F009][S004]
Feature: Scheduled course & enrollment PINs
Step: Merge zomate_fs_courses into zomate_fs_course_enrollments
Logic: Backfill course fields on enrollments, remap FKs, drop courses table.
"""

from alembic import op

revision = "20260606_0012"
down_revision = "20260606_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add merged course columns to enrollments (nullable during backfill).
    op.execute("ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS title VARCHAR(200)")
    op.execute("ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS branch_id INTEGER")
    op.execute("ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS coach_id INTEGER")
    op.execute("ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS scheduled_start TIMESTAMP")
    op.execute("ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS scheduled_end TIMESTAMP")
    op.execute(
        "ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS total_lessons INTEGER NOT NULL DEFAULT 1"
    )
    op.execute(
        "ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS lesson_weekdays VARCHAR(32) NOT NULL DEFAULT '0'"
    )
    op.execute("ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS series_start_date DATE")
    op.execute("ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS series_end_date DATE")

    # 2. Backfill from courses (only when courses table still exists).
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'zomate_fs_courses'
            ) THEN
                UPDATE zomate_fs_course_enrollments e
                SET
                    title = c.title,
                    branch_id = c.branch_id,
                    coach_id = c.coach_id,
                    scheduled_start = c.scheduled_start,
                    scheduled_end = c.scheduled_end,
                    total_lessons = c.total_lessons,
                    lesson_weekdays = c.lesson_weekdays,
                    series_start_date = c.series_start_date,
                    series_end_date = c.series_end_date
                FROM zomate_fs_courses c
                WHERE e.course_id = c.id;
            END IF;
        END $$;
        """
    )

    # 3. Remap attendance.course_id: legacy course id → enrollment id (match student + course).
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'zomate_fs_course_enrollments' AND column_name = 'course_id'
            ) THEN
                UPDATE zomate_fs_attendance a
                SET course_id = e.id
                FROM zomate_fs_course_enrollments e
                WHERE a.course_id IS NOT NULL
                  AND a.course_id = e.course_id
                  AND a.student_id = e.student_id;
            END IF;
        END $$;
        """
    )

    # 4. Remap audit_logs.course_id similarly.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'zomate_fs_course_enrollments' AND column_name = 'course_id'
            ) THEN
                UPDATE zomate_fs_audit_logs al
                SET course_id = e.id
                FROM zomate_fs_course_enrollments e
                WHERE al.course_id IS NOT NULL
                  AND al.course_id = e.course_id
                  AND al.student_id = e.student_id;
            END IF;
        END $$;
        """
    )

    # 5. Soft-delete tombstones: courses → course_enrollments (map old course ids to any enrollment).
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'zomate_fs_course_enrollments' AND column_name = 'course_id'
            ) THEN
                INSERT INTO zomate_fs_deleted_records (entity_type, entity_id, deleted_by_username, deleted_hard, created_at)
                SELECT 'course_enrollments', MIN(e.id), d.deleted_by_username, d.deleted_hard, d.created_at
                FROM zomate_fs_deleted_records d
                JOIN zomate_fs_course_enrollments e ON e.course_id = d.entity_id
                WHERE d.entity_type = 'courses'
                GROUP BY d.entity_id, d.deleted_by_username, d.deleted_hard, d.created_at
                ON CONFLICT DO NOTHING;
                DELETE FROM zomate_fs_deleted_records WHERE entity_type = 'courses';
            ELSE
                UPDATE zomate_fs_deleted_records
                SET entity_type = 'course_enrollments'
                WHERE entity_type = 'courses';
            END IF;
        END $$;
        """
    )

    # 6. Drop legacy enrollment FK to courses and unique constraint.
    op.execute(
        "ALTER TABLE zomate_fs_course_enrollments DROP CONSTRAINT IF EXISTS uq_zomate_fs_enrollment_course_student"
    )
    op.execute(
        "ALTER TABLE zomate_fs_course_enrollments DROP CONSTRAINT IF EXISTS zomate_fs_course_enrollments_course_id_fkey"
    )
    op.execute("ALTER TABLE zomate_fs_course_enrollments DROP COLUMN IF EXISTS course_id")

    # 7. Enforce NOT NULL on backfilled columns.
    op.execute("ALTER TABLE zomate_fs_course_enrollments ALTER COLUMN title SET NOT NULL")
    op.execute("ALTER TABLE zomate_fs_course_enrollments ALTER COLUMN branch_id SET NOT NULL")
    op.execute("ALTER TABLE zomate_fs_course_enrollments ALTER COLUMN coach_id SET NOT NULL")
    op.execute("ALTER TABLE zomate_fs_course_enrollments ALTER COLUMN scheduled_start SET NOT NULL")
    op.execute("ALTER TABLE zomate_fs_course_enrollments ALTER COLUMN scheduled_end SET NOT NULL")

    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'zomate_fs_course_enrollments_branch_id_fkey'
            ) THEN
                ALTER TABLE zomate_fs_course_enrollments
                ADD CONSTRAINT zomate_fs_course_enrollments_branch_id_fkey
                FOREIGN KEY (branch_id) REFERENCES zomate_fs_branches(id);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'zomate_fs_course_enrollments_coach_id_fkey'
            ) THEN
                ALTER TABLE zomate_fs_course_enrollments
                ADD CONSTRAINT zomate_fs_course_enrollments_coach_id_fkey
                FOREIGN KEY (coach_id) REFERENCES zomate_fs_coaches(id);
            END IF;
        END $$;
        """
    )

    # 8. Repoint attendance / audit FKs from courses to enrollments (keep column name course_id).
    op.execute(
        "ALTER TABLE zomate_fs_attendance DROP CONSTRAINT IF EXISTS zomate_fs_attendance_course_id_fkey"
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'zomate_fs_attendance_course_id_fkey'
            ) THEN
                ALTER TABLE zomate_fs_attendance
                ADD CONSTRAINT zomate_fs_attendance_course_id_fkey
                FOREIGN KEY (course_id) REFERENCES zomate_fs_course_enrollments(id) ON DELETE SET NULL;
            END IF;
        END $$;
        """
    )

    op.execute("ALTER TABLE zomate_fs_audit_logs DROP CONSTRAINT IF EXISTS zomate_fs_audit_logs_course_id_fkey")
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint WHERE conname = 'zomate_fs_audit_logs_course_id_fkey'
            ) THEN
                ALTER TABLE zomate_fs_audit_logs
                ADD CONSTRAINT zomate_fs_audit_logs_course_id_fkey
                FOREIGN KEY (course_id) REFERENCES zomate_fs_course_enrollments(id);
            END IF;
        END $$;
        """
    )

    # 9. Drop courses table.
    op.execute("DROP TABLE IF EXISTS zomate_fs_courses CASCADE")


def downgrade() -> None:
    raise NotImplementedError("20260606_0012 downgrade is not supported")
