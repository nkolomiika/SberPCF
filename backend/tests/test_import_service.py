from types import SimpleNamespace
from uuid import uuid4

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.enums import HostStatus
from app.services import ImportService


def _make_scalars_result(items: list[object]) -> MagicMock:
    result = MagicMock()
    result.all.return_value = items
    return result


@pytest.mark.asyncio
async def test_find_matching_host_returns_exact_host() -> None:
    host_id = uuid4()
    existing = SimpleNamespace(id=host_id, ip_address="10.0.0.5", hostname="api.local")
    host_data = SimpleNamespace(ip_address="10.0.0.5", hostname="api.local")
    db = AsyncMock()
    db.scalars = AsyncMock(return_value=_make_scalars_result([existing]))
    service = ImportService(db)

    matched = await service._find_matching_host(uuid4(), host_data)

    assert matched is existing


def test_merge_host_fields_only_fills_missing_values() -> None:
    host = SimpleNamespace(ip_address=None, hostname="api.local", status=HostStatus.UNKNOWN, notes=None)
    host_data = SimpleNamespace(ip_address="10.0.0.5", hostname="api.local", status=HostStatus.UP, notes="Imported from PCF")

    ImportService._merge_host_fields(host, host_data)

    assert host.ip_address == "10.0.0.5"
    assert host.hostname == "api.local"
    assert host.status == HostStatus.UP
    assert host.notes == "Imported from PCF"


def test_merge_endpoint_fields_preserves_existing_data_and_fills_missing() -> None:
    endpoint = SimpleNamespace(
        description=None,
        query_params=[],
        request_body=None,
        request_content_type=None,
        request_headers=[],
    )

    ImportService._merge_endpoint_fields(
        endpoint,
        {
            "description": "Imported endpoint",
            "query_params": [{"name": "role", "value": "admin"}],
            "request_body": "{\"ok\":true}",
            "request_content_type": "application/json",
            "request_headers": [{"name": "X-Test", "value": "1"}],
        },
    )

    assert endpoint.description == "Imported endpoint"
    assert endpoint.query_params == [{"name": "role", "value": "admin"}]
    assert endpoint.request_body == "{\"ok\":true}"
    assert endpoint.request_content_type == "application/json"
    assert endpoint.request_headers == [{"name": "X-Test", "value": "1"}]


def test_load_json_or_yaml_document_supports_yaml() -> None:
    parsed = ImportService._load_json_or_yaml_document(
        """
openapi: 3.0.0
paths:
  /health:
    get:
      summary: Check health
"""
    )

    assert parsed["openapi"] == "3.0.0"
    assert "/health" in parsed["paths"]


def test_resolve_openapi_ref_supports_local_refs() -> None:
    document = {
        "paths": {
            "/users": {
                "$ref": "#/components/pathItems/UsersPath",
            }
        },
        "components": {
            "pathItems": {
                "UsersPath": {
                    "get": {
                        "$ref": "#/components/operations/ListUsers",
                    }
                }
            },
            "operations": {
                "ListUsers": {
                    "summary": "List users",
                }
            },
        },
    }

    path_item = ImportService._resolve_openapi_ref(document, document["paths"]["/users"])
    operation = ImportService._resolve_openapi_ref(document, path_item["get"])

    assert "$ref" in path_item["get"]
    assert operation["summary"] == "List users"


@pytest.mark.asyncio
async def test_import_openapi_skips_duplicate_and_adds_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    project_id = uuid4()
    host_id = uuid4()
    actor_id = uuid4()
    host = SimpleNamespace(id=host_id, hostname="current.local", ip_address=None)
    existing_endpoint = SimpleNamespace(
        description=None,
        query_params=[],
        request_body=None,
        request_content_type=None,
        request_headers=[],
    )
    db = AsyncMock()
    db.scalar = AsyncMock(side_effect=[host, existing_endpoint])
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    monkeypatch.setattr("app.services.AuditService.log", AsyncMock())
    monkeypatch.setattr("app.services.ws_manager.broadcast", AsyncMock())
    service = ImportService(db)

    payload = b"""
openapi: 3.0.0
servers:
  - url: https://api.example.com/v1
paths:
  /users:
    get:
      summary: List users
"""

    result = await service.import_openapi(project_id, host_id, payload, actor_id)

    assert result.endpoints_created == 0
    assert result.endpoints_skipped == 1
    assert result.spec_host == "api.example.com"
    assert result.errors
    assert existing_endpoint.description == "List users"
    db.add.assert_not_called()
