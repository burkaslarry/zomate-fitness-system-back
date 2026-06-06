"""[F002][S001]
Feature: Course Entry & Automation
Step: Drop legacy trial class tables
Logic: Consolidate course kinds onto zomate_fs_course_categories; remove trial_class_kinds/trial_classes.
"""

from alembic import op

revision = "20260606_0009"
down_revision = "20260603_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP TABLE IF EXISTS zomate_fs_trial_classes CASCADE")
    op.execute("DROP TABLE IF EXISTS zomate_fs_trial_class_kinds CASCADE")


def downgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_trial_class_kinds (
            id SERIAL PRIMARY KEY,
            code VARCHAR(64) NOT NULL UNIQUE,
            label_zh VARCHAR(160) NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 0,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc')
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_trial_classes (
            id SERIAL PRIMARY KEY,
            student_id INTEGER NOT NULL REFERENCES zomate_fs_students(id),
            member_hkid VARCHAR(32) NULL,
            type VARCHAR(16) NOT NULL,
            trial_kind_id INTEGER NULL REFERENCES zomate_fs_trial_class_kinds(id),
            coach_id INTEGER NULL REFERENCES zomate_fs_coaches(id),
            branch_id INTEGER NULL REFERENCES zomate_fs_branches(id),
            class_date DATE NOT NULL,
            note TEXT NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc')
        )
        """
    )
