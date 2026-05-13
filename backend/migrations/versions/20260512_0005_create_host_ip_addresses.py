"""Создать таблицу host_ip_addresses и перенести существующие IP из hosts.ip_address.

Revision ID: 20260512_0005
Revises: 20260430_0004
Create Date: 2026-05-12
"""

import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

revision = "20260512_0005"
down_revision = "20260430_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Создаёт таблицу host_ip_addresses и переносит данные из hosts.ip_address.

    Колонка hosts.ip_address оставляется как «основной» IP для обратной совместимости
    и пересчитывается из host_ip_addresses.is_primary в сервисном слое.
    """

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "host_ip_addresses" not in table_names:
        op.create_table(
            "host_ip_addresses",
            sa.Column("id", PG_UUID(as_uuid=True), primary_key=True, nullable=False),
            sa.Column(
                "host_id",
                PG_UUID(as_uuid=True),
                sa.ForeignKey("hosts.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("ip_address", sa.String(length=45), nullable=False),
            sa.Column("label", sa.String(length=100), nullable=True),
            sa.Column(
                "is_primary",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
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
            sa.UniqueConstraint("host_id", "ip_address", name="uq_host_ip_address"),
        )
        op.create_index("ix_host_ip_addresses_host_id", "host_ip_addresses", ["host_id"])

    # Перенос данных: для каждого хоста с непустым ip_address создаём primary-запись.
    rows = bind.execute(
        sa.text("SELECT id, ip_address FROM hosts WHERE ip_address IS NOT NULL AND ip_address <> ''")
    ).fetchall()

    if rows:
        existing_pairs = {
            (str(host_id), ip)
            for host_id, ip in bind.execute(
                sa.text("SELECT host_id, ip_address FROM host_ip_addresses")
            ).fetchall()
        }
        insert_stmt = sa.text(
            "INSERT INTO host_ip_addresses (id, host_id, ip_address, label, is_primary) "
            "VALUES (:id, :host_id, :ip_address, NULL, true)"
        )
        for host_id, ip_value in rows:
            if (str(host_id), ip_value) in existing_pairs:
                continue
            bind.execute(
                insert_stmt,
                {
                    "id": str(uuid.uuid4()),
                    "host_id": str(host_id),
                    "ip_address": ip_value,
                },
            )


def downgrade() -> None:
    """Удаляет таблицу host_ip_addresses; данные обратно в hosts.ip_address не возвращаются."""

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "host_ip_addresses" not in inspector.get_table_names():
        return
    op.drop_index("ix_host_ip_addresses_host_id", table_name="host_ip_addresses")
    op.drop_table("host_ip_addresses")
