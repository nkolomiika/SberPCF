"""Создать таблицу mail_jobs (если она ещё не существует).

Revision ID: 20260420_0003
Revises: 20260416_0002
Create Date: 2026-04-20
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

revision = "20260420_0003"
down_revision = "20260416_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Создаёт таблицу mail_jobs, если её ещё нет в БД."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "mail_jobs" in inspector.get_table_names():
        return
    op.create_table(
        "mail_jobs",
        sa.Column("id", PG_UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "user_id",
            PG_UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_by",
            PG_UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("recipient_email", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("template", sa.String(length=100), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_mail_jobs_recipient_email", "mail_jobs", ["recipient_email"])
    op.create_index("ix_mail_jobs_template", "mail_jobs", ["template"])
    op.create_index("ix_mail_jobs_status", "mail_jobs", ["status"])


def downgrade() -> None:
    """Удаляет таблицу mail_jobs, если она существует."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "mail_jobs" not in inspector.get_table_names():
        return
    op.drop_index("ix_mail_jobs_status", table_name="mail_jobs")
    op.drop_index("ix_mail_jobs_template", table_name="mail_jobs")
    op.drop_index("ix_mail_jobs_recipient_email", table_name="mail_jobs")
    op.drop_table("mail_jobs")
