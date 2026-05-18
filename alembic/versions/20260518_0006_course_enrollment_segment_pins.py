"""[F007][S004]
Feature: Backend platform (FastAPI & PostgreSQL)
Step: Course enrollment installment PIN payloads
Logic: Merge prior heads; optional JSON segments on scheduled enrollments so each payment/tranche PIN is stored.
"""

from alembic import op

revision = "20260518_0006"
down_revision = ("20260515_0004", "20260515_0005")
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS segment_pins_json TEXT NULL"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE zomate_fs_course_enrollments DROP COLUMN IF EXISTS segment_pins_json"
    )
