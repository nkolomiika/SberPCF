"""Create Jira integration tables.

Revision ID: 20260513_0007
Revises: 20260513_0006
Create Date: 2026-05-13
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

revision = "20260513_0007"
down_revision = "20260513_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "jira_instances" not in table_names:
        op.create_table(
            "jira_instances",
            sa.Column("id", PG_UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False, server_default="default"),
            sa.Column("base_url", sa.String(length=1024), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("api_token_encrypted", sa.Text(), nullable=False),
            sa.Column("default_issue_type", sa.String(length=100), nullable=False, server_default="Task"),
            sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_by", PG_UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )

    if "project_jira_links" not in table_names:
        op.create_table(
            "project_jira_links",
            sa.Column("id", PG_UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("project_id", PG_UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
            sa.Column("jira_project_key", sa.String(length=32), nullable=False),
            sa.Column("created_by", PG_UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.UniqueConstraint("project_id", name="uq_project_jira_link_project"),
        )

    if "jira_issue_links" not in table_names:
        op.create_table(
            "jira_issue_links",
            sa.Column("id", PG_UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("vulnerability_id", PG_UUID(as_uuid=True), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
            sa.Column("jira_issue_key", sa.String(length=64), nullable=False),
            sa.Column("jira_issue_url", sa.String(length=1024), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="linked"),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.UniqueConstraint("vulnerability_id", name="uq_jira_issue_link_vulnerability"),
        )
        op.create_index("ix_jira_issue_links_vulnerability_id", "jira_issue_links", ["vulnerability_id"])
        op.create_index("ix_jira_issue_links_jira_issue_key", "jira_issue_links", ["jira_issue_key"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())
    if "jira_issue_links" in table_names:
        op.drop_index("ix_jira_issue_links_jira_issue_key", table_name="jira_issue_links")
        op.drop_index("ix_jira_issue_links_vulnerability_id", table_name="jira_issue_links")
        op.drop_table("jira_issue_links")
    if "project_jira_links" in table_names:
        op.drop_table("project_jira_links")
    if "jira_instances" in table_names:
        op.drop_table("jira_instances")
