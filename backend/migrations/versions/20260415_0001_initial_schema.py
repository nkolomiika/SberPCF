"""Создать начальную схему БД PCF.

Revision ID: 20260415_0001
Revises:
Create Date: 2026-04-15
"""

from alembic import op

from app.database import Base
from app import models  # noqa: F401

# revision identifiers, used by Alembic.
revision = "20260415_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Создаёт все таблицы начальной схемы."""
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    """Удаляет все таблицы начальной схемы."""
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
