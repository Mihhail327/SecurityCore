import json
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
_logger = logging.getLogger(f"{AUDIT_DEFAULT_CHANNEL}.json")
_logger.setLevel(logging.INFO)

# Добавляем обработчик, если его нет
if not _logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    _logger.addHandler(handler)


# Формирование JSON-записи
def _build_json_record(event: str, details: Optional[Dict[str, Any]] = None) -> str:
    """
    Формирует JSON-строку аудита.
    """
    if details is not None and not isinstance(details, dict):
        raise AuditError("Поле 'details' должно быть словарём")

    record = {
        "timestamp": datetime.utcnow().strftime(AUDIT_TIMESTAMP_FORMAT),
        "event": safe_str(event),
        "details": {safe_str(k): safe_str(v) for k, v in (details or {}).items()},
    }

    try:
        json_str = json.dumps(record, ensure_ascii=False)
    except Exception as exc:
        raise AuditError(f"Ошибка сериализации JSON: {exc}")

    if len(json_str) > MAX_LOG_MESSAGE_LENGTH:
        raise AuditError("JSON-запись превышает максимальный размер")

    return json_str


# Основная функция JSON-аудита
def audit_json(event: str, details: Optional[Dict[str, Any]] = None) -> None:
    """
    Записывает событие аудита в формате JSON.

    Пример:
        audit_json("user_login", {"user_id": 42})
    """
    if not isinstance(event, str) or not event.strip():
        raise AuditError("Событие аудита должно быть непустой строкой")

    try:
        json_record = _build_json_record(event, details)
        _logger.info(json_record)
    except Exception as exc:
        raise AuditError(f"Ошибка записи JSON-аудита: {exc}")