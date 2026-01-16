import logging
from datetime import datetime
from typing import Any, Dict, Optional

from securitycore._internal.constants import (
    AUDIT_TIMESTAMP_FORMAT,
    AUDIT_DEFAULT_CHANNEL,
    MAX_LOG_MESSAGE_LENGTH,
)
from securitycore._internal.error import AuditError
from securitycore.utils.helpers import safe_str


# Инициализация логгера
_logger = logging.getLogger(AUDIT_DEFAULT_CHANNEL)
_logger.setLevel(logging.INFO)

# Добавляем обработчик, если его нет
if not _logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    _logger.addHandler(handler)


# Форматирование записи аудита
def _format_audit_record(event: str, details: Optional[Dict[str, Any]] = None) -> str:
    """
    Формирует строку аудита в стандартизированном формате.
    Формат:
        YYYY-MM-DD HH:MM:SS | event | key=value, key=value
    """
    timestamp = datetime.utcnow().strftime(AUDIT_TIMESTAMP_FORMAT)

    if details is None:
        return f"{timestamp} | {event}"

    if not isinstance(details, dict):
        raise AuditError("Поле 'details' должно быть словарём")

    try:
        details_str = ", ".join(
            f"{safe_str(k)}={safe_str(v)}" for k, v in details.items()
        )
    except Exception as exc:
        raise AuditError(f"Ошибка форматирования деталей аудита: {exc}")

    return f"{timestamp} | {event} | {details_str}"


# Основная функция аудита
def audit(event: str, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Записывает событие аудита в лог.

    Пример:
        audit("user_login", {"user_id": 42})
    """
    if not isinstance(event, str) or not event.strip():
        raise AuditError("Событие аудита должно быть непустой строкой")

    record = _format_audit_record(event, details)

    if len(record) > MAX_LOG_MESSAGE_LENGTH:
        raise AuditError("Запись аудита превышает максимальный размер")

    try:
        _logger.info(record)
    except Exception as exc:
        raise AuditError(f"Ошибка записи аудита: {exc}")