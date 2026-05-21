"""Привязать порты к конкретному IP-адресу хоста.

Revision ID: 20260521_0012
Revises: 20260520_0011
Create Date: 2026-05-21

Добавляем колонку ports.ip_address_id (FK на host_ip_addresses) и переносим
уникальный констрейнт с (host_id, port_number, protocol) на
(ip_address_id, port_number, protocol). Это позволяет одному и тому же порту
существовать на разных IP одного хоста и убирает неопределённость, на каком
именно интерфейсе хоста открыт порт.

Для совместимости с возможными существующими данными: колонка добавляется
nullable, заполняется primary-IP хоста, затем переводится в NOT NULL. Если
у хоста нет ни одного IP-адреса в host_ip_addresses, ports такого хоста
удаляются (хост без IP — некорректное состояние после миграции 0005).
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID


revision = "20260521_0012"
down_revision = "20260520_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    port_columns = {col["name"] for col in inspector.get_columns("ports")}

    if "ip_address_id" not in port_columns:
        op.add_column(
            "ports",
            sa.Column(
                "ip_address_id",
                PG_UUID(as_uuid=True),
                sa.ForeignKey("host_ip_addresses.id", ondelete="CASCADE"),
                nullable=True,
            ),
        )

    # Удалить осиротевшие порты (без IP у хоста).
    bind.execute(
        sa.text(
            """
            DELETE FROM ports
            WHERE host_id NOT IN (
                SELECT host_id FROM host_ip_addresses
            )
            """
        )
    )

    # Заполнить ip_address_id из primary-IP хоста (fallback — первый IP по created_at).
    bind.execute(
        sa.text(
            """
            UPDATE ports p
            SET ip_address_id = sub.id
            FROM (
                SELECT DISTINCT ON (host_id) host_id, id
                FROM host_ip_addresses
                ORDER BY host_id, is_primary DESC, created_at ASC
            ) sub
            WHERE p.host_id = sub.host_id
              AND p.ip_address_id IS NULL
            """
        )
    )

    op.alter_column("ports", "ip_address_id", nullable=False)

    existing_unique = {
        c["name"] for c in inspector.get_unique_constraints("ports")
    }
    if "uq_port_host_number_protocol" in existing_unique:
        op.drop_constraint(
            "uq_port_host_number_protocol", "ports", type_="unique"
        )
    if "uq_port_ip_number_protocol" not in existing_unique:
        op.create_unique_constraint(
            "uq_port_ip_number_protocol",
            "ports",
            ["ip_address_id", "port_number", "protocol"],
        )

    existing_indexes = {idx["name"] for idx in inspector.get_indexes("ports")}
    if "ix_ports_ip_address_id" not in existing_indexes:
        op.create_index(
            "ix_ports_ip_address_id", "ports", ["ip_address_id"]
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_unique = {
        c["name"] for c in inspector.get_unique_constraints("ports")
    }
    if "uq_port_ip_number_protocol" in existing_unique:
        op.drop_constraint(
            "uq_port_ip_number_protocol", "ports", type_="unique"
        )
    if "uq_port_host_number_protocol" not in existing_unique:
        op.create_unique_constraint(
            "uq_port_host_number_protocol",
            "ports",
            ["host_id", "port_number", "protocol"],
        )

    existing_indexes = {idx["name"] for idx in inspector.get_indexes("ports")}
    if "ix_ports_ip_address_id" in existing_indexes:
        op.drop_index("ix_ports_ip_address_id", table_name="ports")

    port_columns = {col["name"] for col in inspector.get_columns("ports")}
    if "ip_address_id" in port_columns:
        op.drop_column("ports", "ip_address_id")
