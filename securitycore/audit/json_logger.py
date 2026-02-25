import json
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
    def safe_str(v: Any) -> str: return str(v)[:255]

# Инициализация логгера для JSON-канала
_logger = logging.getLogger(f"{AUDIT_DEFAULT_CHANNEL}.json")

def _build_json_record(event: str, details: Optional[Dict[str, Any]] = None) -> str:
    """Формирует компактную JSON-строку аудита."""
    if details is not None and not isinstance(details, dict):
        raise AuditError("Поле 'details' должно быть словарём")


    record = {
        "timestamp": datetime.now(timezone.utc).strftime(AUDIT_TIMESTAMP_FORMAT),
        "event": safe_str(event),
        "details": {safe_str(k): safe_str(v) for k, v in (details or {}).items()},
    }

    try:
        # Компактная сериализация без лишних пробелов
        json_str = json.dumps(record, ensure_ascii=False, separators=(',', ':'))
    except Exception as exc:
        raise AuditError(f"Ошибка сериализации JSON: {exc}")

    if len(json_str) > MAX_LOG_MESSAGE_LENGTH:
        raise AuditError(f"JSON-запись слишком длинная ({len(json_str)} символов)")

    return json_str

def audit_json(event: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Записывает событие аудита в формате JSON."""
    if not isinstance(event, str) or not event.strip():
        raise AuditError("Событие аудита должно быть непустой строкой")

    try:
        json_record = _build_json_record(event, details)
        _logger.info(json_record)
    except AuditError:
        raise # Пробрасываем наши ошибки дальше
    except Exception as exc:
        raise AuditError(f"Критическая ошибка JSON-аудита: {exc}")