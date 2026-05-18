"""[F007][S002]
Feature: Backend platform (PostgreSQL)
Step: Drop denormalized student lesson_balance
Logic: Remaining credits come only from ``zomate_fs_lesson_ledger``. Run
      ``scripts/sql/backfill_lesson_ledger_from_student_balance.sql`` first if upgrading legacy DBs.
"""

from alembic import op

revision = "20260515_0004"
down_revision = "20260508_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS lesson_balance")


def downgrade() -> None:
    op.execute(
        "ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS "
        "lesson_balance INTEGER NOT NULL DEFAULT 0"
    )
    op.execute("ALTER TABLE zomate_fs_students ALTER COLUMN lesson_balance DROP DEFAULT")
