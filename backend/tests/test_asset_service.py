from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.services import AssetService, JiraIntegrationService


def test_normalize_endpoint_path_replaces_uuid_segments() -> None:
    normalized = AssetService._normalize_endpoint_path("/api/v1/users/550e8400-e29b-41d4-a716-446655440000/orders")

    assert normalized == "/api/v1/users/{UUID}/orders"


def test_apply_raw_request_payload_normalizes_uuid_path() -> None:
    payload = {"request_raw": "GET /api/v1/users/550e8400-e29b-41d4-a716-446655440000?page=1 HTTP/1.1\nHost: demo.local"}

    normalized = AssetService._apply_raw_request_payload(payload)

    assert normalized["path"] == "/api/v1/users/{UUID}"
    assert normalized["query_params"] == [{"name": "page", "value": "1", "required": False, "description": None}]


@pytest.mark.asyncio
async def test_create_endpoint_checks_duplicate_by_normalized_uuid_path(monkeypatch: pytest.MonkeyPatch) -> None:
    project_id = uuid4()
    host_id = uuid4()
    actor_id = uuid4()
    existing_endpoint = SimpleNamespace(
        id=uuid4(),
        description=None,
        query_params=[],
        request_body=None,
        request_content_type=None,
        request_headers=[],
    )
    db = MagicMock()
    db.scalar = AsyncMock(return_value=existing_endpoint)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.add = MagicMock()
    service = AssetService(db)
    service._get_host = AsyncMock(return_value=SimpleNamespace(id=host_id))
    service.audit.log = AsyncMock()
    broadcast_mock = AsyncMock()
    monkeypatch.setattr("app.services.ws_manager.broadcast", broadcast_mock)

    result = await service.create_endpoint(
        project_id,
        host_id,
        {
            "path": "/api/v1/users/550e8400-e29b-41d4-a716-446655440000",
            "method": "GET",
            "query_params": [{"name": "page", "value": "1", "required": False, "description": None}],
            "request_headers": [],
        },
        actor_id,
    )

    assert result is existing_endpoint
    assert existing_endpoint.query_params == [{"name": "page", "value": "1", "required": False, "description": None}]
    db.add.assert_not_called()


def test_apply_raw_request_payload_drops_empty_request_raw() -> None:
    payload = {"path": "/users", "method": "GET", "request_raw": None}

    normalized = AssetService._apply_raw_request_payload(payload)

    assert normalized == {"path": "/users", "method": "GET"}


def test_apply_raw_request_payload_parses_non_empty_request_raw() -> None:
    payload = {"request_raw": "POST /api/v1/users?role=admin HTTP/1.1\nHost: example.local\nContent-Type: application/json\n\n{\"name\":\"alice\"}"}

    normalized = AssetService._apply_raw_request_payload(payload)

    assert "request_raw" not in normalized
    assert normalized["method"] == "POST"
    assert normalized["path"] == "/api/v1/users"
    assert normalized["request_content_type"] == "application/json"
    assert normalized["request_body"] == "{\"name\":\"alice\"}"
    assert normalized["query_params"] == [{"name": "role", "value": "admin", "required": False, "description": None}]


def test_normalize_host_ip_entries_deduplicates_and_marks_primary() -> None:
    entries = AssetService._normalize_host_ip_entries(
        "10.0.0.2",
        [
            {"ip_address": "10.0.0.1", "label": "mgmt", "is_primary": True},
            {"ip_address": "10.0.0.2", "label": "public", "is_primary": False},
            {"ip_address": "10.0.0.1", "label": "duplicate", "is_primary": False},
        ],
    )

    assert [entry["ip_address"] for entry in entries] == ["10.0.0.1", "10.0.0.2"]
    assert [entry["is_primary"] for entry in entries] == [False, True]


def test_jira_secret_roundtrip_does_not_store_plain_text() -> None:
    encrypted = JiraIntegrationService._encrypt_secret("jira-secret")

    assert encrypted != "jira-secret"
    assert JiraIntegrationService._decrypt_secret(encrypted) == "jira-secret"
