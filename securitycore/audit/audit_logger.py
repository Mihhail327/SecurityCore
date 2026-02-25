import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from securitycore._internal.constants import (
    AUDIT_TIMESTAMP_FORMAT,
    AUDIT_DEFAULT_CHANNEL,
    MAX_LOG_MESSAGE_LENGTH,
)
from securitycore._internal.error import AuditError

try:
    from securitycore.utils.helpers import safe_str
except ImportError:
    def safe_str(v: Any) -> str: return str(v)[:100] # Временная заглушка

_logger = logging.getLogger(AUDIT_DEFAULT_CHANNEL)

def _format_audit_record(event: str, details: Optional[Dict[str, Any]] = None) -> str:
    """Формирует строку: YYYY-MM-DD HH:MM:SS | event | k=v, k=v"""
    # Python 3.13 Style: используем timezone-aware datetime
    now = datetime.now(timezone.utc)
    timestamp = now.strftime(AUDIT_TIMESTAMP_FORMAT)

    if not details:
        return f"{timestamp} | {event}"

    if not isinstance(details, dict):
        raise AuditError("Поле 'details' должно быть словарём")

    try:
        # Ограничиваем длину значений внутри деталей, чтобы не раздувать лог
        parts = [f"{safe_str(k)}={safe_str(v)}" for k, v in details.items()]
        details_str = ", ".join(parts)
    except Exception as exc:
        raise AuditError(f"Ошибка форматирования деталей: {exc}")

    return f"{timestamp} | {event} | {details_str}"

def audit(event: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Записывает событие аудита."""
    if not isinstance(event, str) or not event.strip():
        raise AuditError("Событие аудита не может быть пустым")

    record = _format_audit_record(event, details)

    if len(record) > MAX_LOG_MESSAGE_LENGTH:
        # Вместо падения можно просто обрезать, но в безопасности лучше знать о переполнении
        raise AuditError(f"Запись аудита слишком длинная ({len(record)} знаков)")

    _logger.info(record)