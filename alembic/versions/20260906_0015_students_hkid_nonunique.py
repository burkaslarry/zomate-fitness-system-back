"""[F001][S003]
Feature: Student Onboarding
Step: Drop unique constraint on students.hkid — phone remains unique
Logic: Allow duplicate / abbreviated HKIDs; keep non-unique index for lookup.
"""

from alembic import op

revision = "20260906_0015"
down_revision = "20260906_0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_zomate_fs_students_hkid")
    op.execute("ALTER TABLE zomate_fs_students DROP CONSTRAINT IF EXISTS zomate_fs_students_hkid_key")
    op.execute("CREATE INDEX IF NOT EXISTS ix_zomate_fs_students_hkid ON zomate_fs_students (hkid)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_zomate_fs_students_hkid")
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_zomate_fs_students_hkid ON zomate_fs_students (hkid)"
    )
