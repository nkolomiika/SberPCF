from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

import clickhouse_connect

from app.config import get_settings

settings = get_settings()


class ClickHouseAuditStore:
    """Хранилище аудита в ClickHouse с мягким fallback при ошибках."""

    def __init__(self) -> None:
        self.enabled = settings.audit_log_backend.lower() == "clickhouse"
        self._client = None

    def _get_client(self):
        if self._client is None:
            self._client = clickhouse_connect.get_client(
                host=settings.clickhouse_host,
                port=settings.clickhouse_port,
                username=settings.clickhouse_username,
                password=settings.clickhouse_password,
                database=settings.clickhouse_database,
                secure=settings.clickhouse_secure,
            )
        return self._client

    def _ensure_table_sync(self) -> None:
        if not self.enabled:
            return
        client = self._get_client()
        client.command(f"CREATE DATABASE IF NOT EXISTS {settings.clickhouse_database}")
        client.command(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
              id UUID,
              user_id Nullable(UUID),
              username Nullable(String),
              action String,
              entity_type Nullable(String),
              entity_id Nullable(UUID),
              details_json Nullable(String),
              ip_address Nullable(String),
              created_at DateTime64(3, 'UTC')
            )
            ENGINE = MergeTree
            ORDER BY (created_at, action, id)
            """
        )

    async def ensure_table(self) -> None:
        if not self.enabled:
            return
        try:
            await asyncio.to_thread(self._ensure_table_sync)
        except Exception:
            self._client = None

    def _insert_sync(
        self,
        *,
        id_: UUID,
        user_id: UUID | None,
        username: str | None,
        action: str,
        entity_type: str | None,
        entity_id: UUID | None,
        details: dict | None,
        ip_address: str | None,
        created_at: datetime,
    ) -> None:
        client = self._get_client()
        client.insert(
            "audit_logs",
            [[id_, user_id, username, action, entity_type, entity_id, json.dumps(details) if details else None, ip_address, created_at]],
            column_names=["id", "user_id", "username", "action", "entity_type", "entity_id", "details_json", "ip_address", "created_at"],
        )

    async def insert(
        self,
        *,
        user_id: UUID | None,
        username: str | None,
        action: str,
        entity_type: str | None,
        entity_id: UUID | None,
        details: dict | None,
        ip_address: str | None,
        created_at: datetime | None = None,
    ) -> UUID | None:
        if not self.enabled:
            return None
        log_id = uuid4()
        created = created_at or datetime.now(UTC)
        try:
            await asyncio.to_thread(
                self._insert_sync,
                id_=log_id,
                user_id=user_id,
                username=username,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
                ip_address=ip_address,
                created_at=created,
            )
        except Exception:
            return None
        return log_id

    def _build_where_clause(self, filters: dict) -> tuple[str, dict]:
        conditions: list[str] = []
        params: dict = {}
        if filters.get("user_id"):
            conditions.append("user_id = {user_id:UUID}")
            params["user_id"] = str(filters["user_id"])
        if filters.get("username"):
            conditions.append("positionCaseInsensitive(ifNull(username, ''), {username:String}) > 0")
            params["username"] = filters["username"].strip()
        if filters.get("action"):
            conditions.append("positionCaseInsensitive(action, {action:String}) > 0")
            params["action"] = filters["action"].strip()
        if filters.get("entity_type"):
            conditions.append("positionCaseInsensitive(ifNull(entity_type, ''), {entity_type:String}) > 0")
            params["entity_type"] = filters["entity_type"].strip()
        if filters.get("entity_id"):
            conditions.append("toString(entity_id) = {entity_id:String}")
            params["entity_id"] = str(filters["entity_id"])
        if filters.get("ip_address"):
            conditions.append("positionCaseInsensitive(ifNull(ip_address, ''), {ip_address:String}) > 0")
            params["ip_address"] = filters["ip_address"].strip()
        if filters.get("query"):
            conditions.append(
                "("
                "positionCaseInsensitive(action, {query:String}) > 0 OR "
                "positionCaseInsensitive(ifNull(entity_type, ''), {query:String}) > 0 OR "
                "positionCaseInsensitive(ifNull(username, ''), {query:String}) > 0 OR "
                "positionCaseInsensitive(ifNull(details_json, ''), {query:String}) > 0 OR "
                "positionCaseInsensitive(ifNull(ip_address, ''), {query:String}) > 0"
                ")"
            )
            params["query"] = filters["query"].strip()
        if filters.get("created_from"):
            conditions.append("created_at >= parseDateTime64BestEffort({created_from:String}, 3)")
            params["created_from"] = filters["created_from"]
        if filters.get("created_to"):
            conditions.append("created_at <= parseDateTime64BestEffort({created_to:String}, 3)")
            params["created_to"] = filters["created_to"]
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return where_clause, params

    def _list_sync(self, page: int, size: int, filters: dict) -> tuple[list[dict], int]:
        client = self._get_client()
        where_clause, params = self._build_where_clause(filters)
        count_result = client.query(f"SELECT count() FROM audit_logs {where_clause}", parameters=params)
        total = int(count_result.result_rows[0][0]) if count_result.result_rows else 0
        offset = (page - 1) * size
        query_result = client.query(
            f"""
            SELECT id, user_id, username, action, entity_type, entity_id, details_json, ip_address, created_at
            FROM audit_logs
            {where_clause}
            ORDER BY created_at DESC
            LIMIT {size} OFFSET {offset}
            """,
            parameters=params,
        )
        items: list[dict] = []
        for row in query_result.result_rows:
            details = None
            if row[6]:
                try:
                    details = json.loads(row[6])
                except json.JSONDecodeError:
                    details = {"raw": row[6]}
            items.append(
                {
                    "id": row[0],
                    "user_id": row[1],
                    "username": row[2],
                    "action": row[3],
                    "entity_type": row[4],
                    "entity_id": row[5],
                    "details": details,
                    "ip_address": row[7],
                    "created_at": row[8],
                }
            )
        return items, total

    async def list_logs(self, page: int, size: int, filters: dict) -> tuple[list[dict], int] | None:
        if not self.enabled:
            return None
        try:
            return await asyncio.to_thread(self._list_sync, page, size, filters)
        except Exception:
            return None


audit_store = ClickHouseAuditStore()
