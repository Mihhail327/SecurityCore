import html
from securitycore._internal.error import SecurityViolationError
# Импортируем то, что реально есть в regexes.py
from securitycore._internal.regexes import (
    XSS_DANGEROUS_TAGS,
    # Если ты решишь добавить остальные, добавь их и сюда
)
from securitycore._internal.constants import (
    MAX_INPUT_LENGTH,
)
from securitycore.audit.audit_logger import audit


def ensure_no_xss(value: str) -> None:
    """Проверка на XSS векторы через опасные теги."""
    if not isinstance(value, str):
        return

    if len(value) > MAX_INPUT_LENGTH:
        raise SecurityViolationError("Ввод слишком длинный")

    # Используем твой агрессивный паттерн для тегов
    if XSS_DANGEROUS_TAGS.search(value):
        audit("xss_attempt", {"payload": value[:100]})
        raise SecurityViolationError("Обнаружен запрещенный HTML-тег (XSS риск)")


def sanitize_xss(value: str) -> str:
    """Очистка и экранирование."""
    if not isinstance(value, str):
        raise SecurityViolationError("Ожидалась строка")

    # Вырезаем опасные теги перед экранированием
    cleaned = XSS_DANGEROUS_TAGS.sub("", value)

    return html.escape(cleaned, quote=True).strip()