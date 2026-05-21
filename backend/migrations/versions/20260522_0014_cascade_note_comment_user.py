"""Каскадное удаление комментариев к заметкам при удалении пользователя.

Revision ID: 20260522_0014
Revises: 20260522_0013
Create Date: 2026-05-22

Меняем FK `project_note_comments.user_id` -> `users.id` так, чтобы при удалении
пользователя его комментарии к страницам заметок удалялись каскадно.
До этого FK был без ondelete, и попытка удалить пользователя ловила
ForeignKeyViolationError.
"""

from alembic import op


revision = "20260522_0014"
down_revision = "20260522_0013"
branch_labels = None
depends_on = None


_FK_NAME = "project_note_comments_user_id_fkey"
_TABLE = "project_note_comments"


def upgrade() -> None:
    op.drop_constraint(_FK_NAME, _TABLE, type_="foreignkey")
    op.create_foreign_key(
        _FK_NAME,
        _TABLE,
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(_FK_NAME, _TABLE, type_="foreignkey")
    op.create_foreign_key(
        _FK_NAME,
        _TABLE,
        "users",
        ["user_id"],
        ["id"],
    )
