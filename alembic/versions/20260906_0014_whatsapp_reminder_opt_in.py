"""[F005][S003]
Feature: Balance Sync & Integrations / WhatsApp
Step: Persist WhatsApp reminder opt-in on students
Logic: ADD COLUMN IF NOT EXISTS whatsapp_reminder_opt_in (+ timestamp).
"""

from alembic import op

revision = "20260906_0014"
down_revision = "20260607_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE zomate_fs_students
        ADD COLUMN IF NOT EXISTS whatsapp_reminder_opt_in BOOLEAN NOT NULL DEFAULT TRUE
        """
    )
    op.execute(
        """
        ALTER TABLE zomate_fs_students
        ADD COLUMN IF NOT EXISTS whatsapp_reminder_opt_in_at TIMESTAMP NULL
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS whatsapp_reminder_opt_in_at")
    op.execute("ALTER TABLE zomate_fs_students DROP COLUMN IF EXISTS whatsapp_reminder_opt_in")
