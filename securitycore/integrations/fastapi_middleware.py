from typing import Callable

try:
    from fastapi import Request, Response

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from securitycore.audit.audit_logger import audit


class SecurityAuditMiddleware:
    """
    Middleware для автоматического аудита и базовой защиты в FastAPI.
    Применяет мониторинг (IDS) к query-параметрам и логирует подозрительную активность.
    Добавляет базовые Security Headers.
    """

    def __init__(self, app=None):
        if not FASTAPI_AVAILABLE:
            raise ImportError(
                "FastAPI не установлен. Для использования этого Middleware установите пакет: "
                "pip install securitycore[fastapi]"
            )
        self.app = app

    async def __call__(self, request: "Request", call_next: Callable) -> "Response":
        # 1. Анализ Query параметров (IDS слой)
        for key, value in request.query_params.items():
            value_lower = value.lower()
            if (
                "<script" in value_lower
                or "javascript:" in value_lower
                or "onerror=" in value_lower
            ):
                audit(
                    "xss_attempt",
                    {"key": key, "path": request.url.path, "payload": value[:50]},
                )

            # Простейший SQL IDS паттерн (UNION SELECT, DROP TABLE и т.д.)
            if "union select" in value_lower or "drop table" in value_lower:
                audit("sql_injection_attempt", {"key": key, "path": request.url.path})

        # 2. Передача управления следующему слою (роутеру/другим middleware)
        response = await call_next(request)

        # 3. Установка Security Headers по умолчанию
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        return response
