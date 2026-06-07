"""[F003][S001]
Feature: Coach dashboard scheduling
Step: Pending queue flag on course enrollments
Logic: coach_time_confirmed=False on zomate_fs_course_enrollments until coach assigns a slot.
"""

from alembic import op

revision = "20260606_0011"
down_revision = "20260606_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_courses DROP COLUMN IF EXISTS coach_time_confirmed")
    op.execute(
        "ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS coach_time_confirmed BOOLEAN NOT NULL DEFAULT TRUE"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_course_enrollments DROP COLUMN IF EXISTS coach_time_confirmed")
