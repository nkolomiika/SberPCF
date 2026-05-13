"""Создать таблицы project_notes и project_note_comments.

Revision ID: 20260430_0004
Revises: 20260420_0003
Create Date: 2026-04-30
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

revision = "20260430_0004"
down_revision = "20260420_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "project_notes" not in table_names:
        op.create_table(
            "project_notes",
            sa.Column("id", PG_UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("project_id", PG_UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
            sa.Column("parent_id", PG_UUID(as_uuid=True), sa.ForeignKey("project_notes.id", ondelete="CASCADE"), nullable=True),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("content", sa.Text(), nullable=True),
            sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_by", PG_UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("updated_by", PG_UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.UniqueConstraint("project_id", "parent_id", "title", name="uq_project_note_sibling_title"),
        )
        op.create_index("ix_project_notes_project_id", "project_notes", ["project_id"])
        op.create_index("ix_project_notes_parent_id", "project_notes", ["parent_id"])

    if "project_note_comments" not in table_names:
        op.create_table(
            "project_note_comments",
            sa.Column("id", PG_UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("project_id", PG_UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
            sa.Column("note_id", PG_UUID(as_uuid=True), sa.ForeignKey("project_notes.id", ondelete="CASCADE"), nullable=False),
            sa.Column("user_id", PG_UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_project_note_comments_project_id", "project_note_comments", ["project_id"])
        op.create_index("ix_project_note_comments_note_id", "project_note_comments", ["note_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "project_note_comments" in table_names:
        op.drop_index("ix_project_note_comments_note_id", table_name="project_note_comments")
        op.drop_index("ix_project_note_comments_project_id", table_name="project_note_comments")
        op.drop_table("project_note_comments")

    if "project_notes" in table_names:
        op.drop_index("ix_project_notes_parent_id", table_name="project_notes")
        op.drop_index("ix_project_notes_project_id", table_name="project_notes")
        op.drop_table("project_notes")
