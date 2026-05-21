"""Add note_comment_id to notifications.

Revision ID: 20260514_0010
Revises: 20260514_0009
Create Date: 2026-05-14

Расширяем уведомления, чтобы они могли ссылаться на комментарий заметки
(а не только на vulnerability-комментарий). Колонка nullable + ON DELETE SET NULL,
аналогично существующей comment_id.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260514_0010"
down_revision = "20260514_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "notifications",
        sa.Column("note_comment_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_notifications_note_comment_id",
        "notifications",
        "project_note_comments",
        ["note_comment_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_notifications_note_comment_id", "notifications", type_="foreignkey")
    op.drop_column("notifications", "note_comment_id")
