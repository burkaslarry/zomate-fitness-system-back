"""[F003][S009]
Feature: Coach Session Management
Step: Persist one-lesson cancellation and reschedule overrides
Logic: Keep the recurring enrollment intact while storing exceptions by original lesson date.
"""

from alembic import op

revision = "20260928_0016"
down_revision = "20260906_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_course_session_overrides (
            id SERIAL PRIMARY KEY,
            enrollment_id INTEGER NOT NULL REFERENCES zomate_fs_course_enrollments(id) ON DELETE CASCADE,
            original_date DATE NOT NULL,
            action VARCHAR(24) NOT NULL,
            rescheduled_start TIMESTAMP NULL,
            rescheduled_end TIMESTAMP NULL,
            reason VARCHAR(255) NULL,
            created_by_username VARCHAR(120) NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_zomate_fs_session_override UNIQUE (enrollment_id, original_date)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_zomate_fs_course_session_overrides_enrollment_id "
        "ON zomate_fs_course_session_overrides (enrollment_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_zomate_fs_course_session_overrides_original_date "
        "ON zomate_fs_course_session_overrides (original_date)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS zomate_fs_course_session_overrides")
