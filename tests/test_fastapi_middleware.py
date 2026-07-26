import pytest
import asyncio
from securitycore.integrations.fastapi_middleware import (
    SecurityAuditMiddleware,
    FASTAPI_AVAILABLE,
)

if FASTAPI_AVAILABLE:
    from fastapi import Request, Response


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI is not installed")
def test_fastapi_middleware_security_headers(caplog):
    middleware = SecurityAuditMiddleware()

    # Имитируем запрос с query_params
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "headers": [],
        "query_string": b"param=clean",
    }
    request = Request(scope)

    async def mock_call_next(req):
        return Response(content="OK", status_code=200)

    response = asyncio.run(middleware(request, mock_call_next))

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-XSS-Protection"] == "1; mode=block"


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI is not installed")
def test_fastapi_middleware_ids_detection(caplog):
    middleware = SecurityAuditMiddleware()

    scope_xss = {
        "type": "http",
        "method": "GET",
        "path": "/search",
        "headers": [],
        "query_string": b"q=%3Cscript%3Ealert(1)%3C/script%3E",
    }
    request_xss = Request(scope_xss)

    async def mock_call_next(req):
        return Response(content="OK", status_code=200)

    with caplog.at_level("INFO"):
        asyncio.run(middleware(request_xss, mock_call_next))

    assert "xss_attempt" in caplog.text

    scope_sql = {
        "type": "http",
        "method": "GET",
        "path": "/search",
        "headers": [],
        "query_string": b"q=UNION+SELECT+*+FROM+users",
    }
    request_sql = Request(scope_sql)

    with caplog.at_level("INFO"):
        asyncio.run(middleware(request_sql, mock_call_next))

    assert "sql_injection_attempt" in caplog.text
