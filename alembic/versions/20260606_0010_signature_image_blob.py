"""[F001][S004]
Feature: Student Onboarding
Step: Persist signature PNG in PostgreSQL
Logic: Render ephemeral disk loses /uploads files; store blob for reliable admin display.
"""

from alembic import op

revision = "20260606_0010"
down_revision = "20260606_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_students ADD COLUMN IF NOT EXISTS signature_image_blob BYTEA NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS signature_image_blob")
