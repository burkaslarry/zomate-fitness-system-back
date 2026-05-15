"""[F007][S004]
Feature: Backend platform (FastAPI & PostgreSQL)
Step: (see Logic)
Logic: Drop legacy ``zomate_fs_students.pin_code``; check-in PINs live on course enrollments only.
"""

from alembic import op

revision = "20260515_0005"
down_revision = "20260509_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS pin_code")


def downgrade() -> None:
    op.execute(
        "ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS "
        "pin_code VARCHAR(10) NOT NULL DEFAULT '1234'"
    )
