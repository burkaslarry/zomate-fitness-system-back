"""[F007][S002]
Feature: Backend platform (PostgreSQL)
Step: Drop denormalized student lesson_balance
Logic: Remaining credits come only from ``zomate_fs_lesson_ledger``. Run
      ``scripts/sql/backfill_lesson_ledger_from_student_balance.sql`` first if upgrading legacy DBs.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260515_0004"
down_revision = "20260508_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("zomate_fs_students", "lesson_balance")


def downgrade() -> None:
    op.add_column(
        "zomate_fs_students",
        sa.Column("lesson_balance", sa.Integer(), nullable=False, server_default="0"),
    )
    op.alter_column("zomate_fs_students", "lesson_balance", server_default=None)
