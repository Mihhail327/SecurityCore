from typing import Callable, Optional, Dict

try:
    from fastapi import Request, Response

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from securitycore.audit.audit_logger import audit
from securitycore._internal.regexes import XSS_DANGEROUS_TAGS, SQL_INJECTION_PATTERN

DEFAULT_SECURITY_HEADERS: Dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


class SecurityAuditMiddleware:
    """
    Middleware для автоматического аудита и базовой защиты в FastAPI.
    Применяет мониторинг (IDS) к query-параметрам и логирует подозрительную активность.
    Добавляет настраиваемые Security Headers.
    """

    def __init__(
        self,
        app=None,
        security_headers: Optional[Dict[str, str]] = None,
    ):
        if not FASTAPI_AVAILABLE:
            raise ImportError(
                "FastAPI не установлен. Для использования этого Middleware установите пакет: "
                "pip install securitycore[fastapi]"
            )
        self.app = app
        self.security_headers = (
            security_headers if security_headers is not None else DEFAULT_SECURITY_HEADERS
        )

    async def __call__(self, request: "Request", call_next: Callable) -> "Response":
        # 1. Анализ Query параметров (IDS слой)
        for key, value in request.query_params.items():
            if XSS_DANGEROUS_TAGS.search(value):
                audit(
                    "xss_attempt",
                    {"key": key, "path": request.url.path, "payload": value[:50]},
                )

            if SQL_INJECTION_PATTERN.search(value):
                audit(
                    "sql_injection_attempt",
                    {"key": key, "path": request.url.path, "payload": value[:50]},
                )

        # 2. Передача управления следующему слою
        response = await call_next(request)

        # 3. Установка Security Headers по умолчанию или кастомных
        for header_name, header_value in self.security_headers.items():
            response.headers[header_name] = header_value

        return response
