"""activity log table

Revision ID: 20260430_0002
Revises: 20260430_0001
Create Date: 2026-04-30
"""

from alembic import op

revision = "20260430_0002"
down_revision = "20260430_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS zomate_fs_activity_log (
            id SERIAL PRIMARY KEY,
            member_hkid VARCHAR(32) NOT NULL,
            type VARCHAR(80) NOT NULL,
            ref_id INTEGER NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_activity_log_member_hkid ON zomate_fs_activity_log (member_hkid)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_activity_log_created_at ON zomate_fs_activity_log (created_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS zomate_fs_activity_log")
