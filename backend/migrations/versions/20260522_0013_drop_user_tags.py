"""Удалить колонку users.tags.

Revision ID: 20260522_0013
Revises: 20260521_0012
Create Date: 2026-05-22

Теги пользователя оказались неиспользуемым функционалом. Колонка JSON `tags`
удаляется из таблицы users. Все упоминания на стороне backend/frontend убраны.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260522_0013"
down_revision = "20260521_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("users")}
    if "tags" in columns:
        op.drop_column("users", "tags")


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("users")}
    if "tags" not in columns:
        op.add_column("users", sa.Column("tags", sa.JSON(), nullable=True))
