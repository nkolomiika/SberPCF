from app.services import AssetService


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
