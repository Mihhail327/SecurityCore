import re
import html

from securitycore._internal.error import SecurityViolationError
from securitycore._internal.regexes import (
    XSS_SCRIPT_PATTERN,
    XSS_EVENT_HANDLER_PATTERN,
    XSS_JS_PROTOCOL_PATTERN,
)
from securitycore._internal.constants import (
    MAX_INPUT_LENGTH,
)


# Проверка на XSS
def ensure_no_xss(value: str) -> None:
    """
    Проверяет, что строка не содержит XSS-векторов:
    - <script>
    - javascript:
    - onerror=, onclick=, onload= и т.д.
    """
    if not isinstance(value, str):
        raise SecurityViolationError("Ожидалась строка")

    if len(value) > MAX_INPUT_LENGTH:
        raise SecurityViolationError("Ввод слишком длинный")

    if XSS_SCRIPT_PATTERN.search(value):
        raise SecurityViolationError("Обнаружена попытка XSS через <script>")

    if XSS_EVENT_HANDLER_PATTERN.search(value):
        raise SecurityViolationError("Обнаружена попытка XSS через event handler")

    if XSS_JS_PROTOCOL_PATTERN.search(value):
        raise SecurityViolationError("Обнаружена попытка XSS через javascript:")


# Фильтрация XSS
def sanitize_xss(value: str) -> str:
    """
    Экранирует HTML и удаляет опасные конструкции.
    Не гарантирует 100% защиту, но безопасна для отображения.
    """
    if not isinstance(value, str):
        raise SecurityViolationError("Ожидалась строка")

    cleaned = html.escape(value, quote=True)

    cleaned = XSS_SCRIPT_PATTERN.sub("", cleaned)
    cleaned = XSS_EVENT_HANDLER_PATTERN.sub("", cleaned)
    cleaned = XSS_JS_PROTOCOL_PATTERN.sub("", cleaned)

    return cleaned


# Комплексная проверка
def ensure_safe_html(value: str) -> str:
    """
    Полная проверка HTML:
    - отсутствие XSS
    - безопасное отображение
    """
    ensure_no_xss(value)
    return sanitize_xss(value)