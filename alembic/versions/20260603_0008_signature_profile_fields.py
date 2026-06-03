"""[F001][S004]
Feature: Student Onboarding
Step: Canvas signature and mobile traceability
Logic: Store upload URL for signature image and previous mobile number for admin edits.
"""

from alembic import op

revision = "20260603_0008"
down_revision = "20260518_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS signature_image_url VARCHAR(512) NULL")
    op.execute("ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS used_mobile_number VARCHAR(30) NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS used_mobile_number")
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS signature_image_url")
