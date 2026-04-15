import pytest
from starlette.requests import Request

from app.dependencies import enforce_csrf
from app.exceptions import ForbiddenError


def _request(method: str) -> Request:
    scope = {
        "type": "http",
        "method": method,
        "path": "/",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
        "scheme": "http",
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_enforce_csrf_skips_get_requests() -> None:
    await enforce_csrf(_request("GET"), origin=None)


@pytest.mark.asyncio
async def test_enforce_csrf_requires_origin_on_post_tc_auth_005() -> None:
    with pytest.raises(ForbiddenError, match="Отсутствует заголовок Origin"):
        await enforce_csrf(_request("POST"), origin=None)


@pytest.mark.asyncio
async def test_enforce_csrf_rejects_unknown_origin_tc_sec_005() -> None:
    with pytest.raises(ForbiddenError, match="Недопустимый Origin"):
        await enforce_csrf(_request("PATCH"), origin="http://evil.local")


@pytest.mark.asyncio
async def test_enforce_csrf_accepts_allowed_origin() -> None:
    await enforce_csrf(_request("DELETE"), origin="http://localhost:3000")
