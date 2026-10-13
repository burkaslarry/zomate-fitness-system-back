"""[F005][S003] Store course-specific payment facts for the agreed WhatsApp templates."""

from alembic import op

revision = "20261013_0017"
down_revision = "20260928_0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """[F007][S002] Add nullable state without changing any existing attendance or payment rows."""
    op.execute("ALTER TABLE zomate_fs_course_enrollments ADD COLUMN IF NOT EXISTS payment_state_json TEXT NULL")


def downgrade() -> None:
    """[F007][S002] Reverse the column migration when explicitly requested."""
    op.execute("ALTER TABLE zomate_fs_course_enrollments DROP COLUMN IF EXISTS payment_state_json")
