"""Add os_type column to hosts.

Revision ID: 20260514_0008
Revises: 20260513_0007
Create Date: 2026-05-14

Postgres enum host_os_type использует UPPERCASE-ключи (соответствует конвенции
проекта: host_status, vuln_severity и др.). Python OsType определён как
``WINDOWS = "windows"`` — SQLAlchemy по умолчанию маппит на .name (UPPERCASE),
а Pydantic возвращает .value (lowercase) во фронтенд.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260514_0008"
down_revision = "20260513_0007"
branch_labels = None
depends_on = None


OS_TYPE_VALUES = ("WINDOWS", "LINUX", "MACOS", "FREEBSD", "ANDROID", "IOS", "OTHER", "UNKNOWN")


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("hosts")}
    if "os_type" in columns:
        return

    host_os_type = sa.Enum(*OS_TYPE_VALUES, name="host_os_type")
    host_os_type.create(bind, checkfirst=True)

    op.add_column(
        "hosts",
        sa.Column(
            "os_type",
            sa.Enum(*OS_TYPE_VALUES, name="host_os_type", create_type=False),
            nullable=False,
            server_default="UNKNOWN",
        ),
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("hosts")}
    if "os_type" in columns:
        op.drop_column("hosts", "os_type")
    sa.Enum(name="host_os_type").drop(bind, checkfirst=True)
