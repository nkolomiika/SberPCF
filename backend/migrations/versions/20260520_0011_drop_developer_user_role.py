"""Drop 'DEVELOPER' value from user_role enum.

Revision ID: 20260520_0011
Revises: 20260514_0010
Create Date: 2026-05-20

Удаляем роль DEVELOPER из enum user_role. Пользователи, у которых была эта роль,
переводятся в PENTESTER. PostgreSQL не поддерживает удаление значений enum напрямую,
поэтому пересоздаём тип.

В БД значения enum хранятся в верхнем регистре (имена Python enum: ADMIN, PENTESTER,
DEVELOPER), так как SQLAlchemy по умолчанию использует enum names, а не values.
"""

from alembic import op


revision = "20260520_0011"
down_revision = "20260514_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute(
        "UPDATE users SET role = 'PENTESTER' "
        "WHERE role::text IN ('DEVELOPER', 'developer')"
    )
    op.execute("ALTER TYPE user_role RENAME TO user_role_old")
    op.execute("CREATE TYPE user_role AS ENUM ('ADMIN', 'PENTESTER')")
    op.execute(
        "ALTER TABLE users ALTER COLUMN role TYPE user_role USING role::text::user_role"
    )
    op.execute("DROP TYPE user_role_old")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute("ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'DEVELOPER'")
