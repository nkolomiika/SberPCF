"""Удалить поле os из таблицы hosts.

Revision ID: 20260416_0002
Revises: 20260415_0001
Create Date: 2026-04-16
"""

from alembic import op
import sqlalchemy as sa


revision = "20260416_0002"
down_revision = "20260415_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Удаляет колонку os из hosts, если она существует."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("hosts")}
    if "os" in columns:
        op.drop_column("hosts", "os")


def downgrade() -> None:
    """Возвращает колонку os в hosts."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("hosts")}
    if "os" not in columns:
        op.add_column("hosts", sa.Column("os", sa.String(length=255), nullable=True))
