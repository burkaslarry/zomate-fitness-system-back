"""[F007][S002] Fractional lesson credits (0.5 step) on ledger.

Revision ID: 20260624_0018
Revises: 20261013_0017
Create Date: 2026-06-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20260624_0018"
down_revision: Union[str, None] = "20261013_0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "zomate_fs_lesson_ledger",
        "delta_lessons",
        existing_type=sa.Integer(),
        type_=sa.Numeric(10, 1),
        existing_nullable=False,
        postgresql_using="delta_lessons::numeric(10,1)",
    )


def downgrade() -> None:
    op.alter_column(
        "zomate_fs_lesson_ledger",
        "delta_lessons",
        existing_type=sa.Numeric(10, 1),
        type_=sa.Integer(),
        existing_nullable=False,
        postgresql_using="ROUND(delta_lessons)::integer",
    )