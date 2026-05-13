"""Create agent API token tables.

Revision ID: 20260513_0006
Revises: 20260512_0005
Create Date: 2026-05-13
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

revision = "20260513_0006"
down_revision = "20260512_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "agent_api_tokens" not in table_names:
        op.create_table(
            "agent_api_tokens",
            sa.Column("id", PG_UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("token_hash", sa.String(length=255), nullable=False),
            sa.Column("token_prefix", sa.String(length=32), nullable=False),
            sa.Column("scopes", sa.JSON(), nullable=False),
            sa.Column("all_projects", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("created_by", PG_UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.UniqueConstraint("token_hash", name="uq_agent_api_tokens_token_hash"),
        )
        op.create_index("ix_agent_api_tokens_token_hash", "agent_api_tokens", ["token_hash"])
        op.create_index("ix_agent_api_tokens_token_prefix", "agent_api_tokens", ["token_prefix"])

    if "agent_api_token_project_grants" not in table_names:
        op.create_table(
            "agent_api_token_project_grants",
            sa.Column("id", PG_UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column("token_id", PG_UUID(as_uuid=True), sa.ForeignKey("agent_api_tokens.id", ondelete="CASCADE"), nullable=False),
            sa.Column("project_id", PG_UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.UniqueConstraint("token_id", "project_id", name="uq_agent_api_token_project"),
        )
        op.create_index("ix_agent_api_token_project_grants_token_id", "agent_api_token_project_grants", ["token_id"])
        op.create_index("ix_agent_api_token_project_grants_project_id", "agent_api_token_project_grants", ["project_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())
    if "agent_api_token_project_grants" in table_names:
        op.drop_index("ix_agent_api_token_project_grants_project_id", table_name="agent_api_token_project_grants")
        op.drop_index("ix_agent_api_token_project_grants_token_id", table_name="agent_api_token_project_grants")
        op.drop_table("agent_api_token_project_grants")
    if "agent_api_tokens" in table_names:
        op.drop_index("ix_agent_api_tokens_token_prefix", table_name="agent_api_tokens")
        op.drop_index("ix_agent_api_tokens_token_hash", table_name="agent_api_tokens")
        op.drop_table("agent_api_tokens")
