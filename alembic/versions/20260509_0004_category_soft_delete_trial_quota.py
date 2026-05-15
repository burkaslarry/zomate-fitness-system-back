"""[F007][S004]
Feature: Backend platform (FastAPI & PostgreSQL)
Step: (see Logic)
Logic: Revision: category soft-delete and trial quota migration.
"""

from alembic import op

revision = "20260509_0004"
down_revision = "20260508_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE zomate_fs_course_categories ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT FALSE"
    )
    op.execute(
        "ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS coach_trial_quota_remaining INTEGER NOT NULL DEFAULT 1"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_zomate_fs_course_categories_deleted ON zomate_fs_course_categories (is_deleted)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_zomate_fs_course_categories_deleted")
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS coach_trial_quota_remaining")
    op.execute("ALTER TABLE zomate_fs_course_categories DROP COLUMN IF EXISTS is_deleted")
