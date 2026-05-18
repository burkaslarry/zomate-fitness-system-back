"""[F001][S001]
Feature: Student Onboarding
Step: Required date-of-birth capture
Logic: Add nullable DOB column so new forms require DOB while existing production rows remain valid.
"""

from alembic import op

revision = "20260518_0007"
down_revision = "20260518_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS date_of_birth DATE NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS date_of_birth")
