"""[F003][S002]
Feature: Coach authentication
Step: Link AppUser.coach_id to coach profile for admin-managed logins
Logic: Nullable unique FK on zomate_fs_users.coach_id.
"""

from alembic import op

revision = "20260607_0013"
down_revision = "20260606_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE zomate_fs_users
        ADD COLUMN IF NOT EXISTS coach_id INTEGER UNIQUE REFERENCES zomate_fs_coaches(id)
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE zomate_fs_users DROP COLUMN IF EXISTS coach_id")
