import re

from securitycore._internal.error import SecurityViolationError
from securitycore._internal.regexes import (
    SQL_INJECTION_PATTERN,
    SQL_META_CHARS_PATTERN,
)
from securitycore._internal.constants import (
    MAX_SQL_INPUT_LENGTH,
)


# ---------------------------------------------------------
# Проверка на SQL-инъекцию
# ---------------------------------------------------------
def ensure_no_sql_injection(value: str) -> None:
    """
    Проверяет, что строка не содержит SQL-инъекций.
    Использует строгие паттерны из regexes.py.
    """
    if not isinstance(value, str):
        raise SecurityViolationError("SQL-параметр должен быть строкой")

    if len(value) > MAX_SQL_INPUT_LENGTH:
        raise SecurityViolationError("SQL-параметр слишком длинный")

    if SQL_INJECTION_PATTERN.search(value):
        raise SecurityViolationError("Обнаружена попытка SQL-инъекции")

    if SQL_META_CHARS_PATTERN.search(value):
        raise SecurityViolationError("Строка содержит опасные SQL-символы")


# ---------------------------------------------------------
# Фильтрация опасных символов
# ---------------------------------------------------------
def sanitize_sql_input(value: str) -> str:
    """
    Удаляет опасные SQL-метасимволы.
    Не гарантирует безопасность, но снижает риск.
    """
    if not isinstance(value, str):
        raise SecurityViolationError("SQL-параметр должен быть строкой")

    cleaned = SQL_META_CHARS_PATTERN.sub("", value)
    return cleaned.strip()


# ---------------------------------------------------------
# Комплексная проверка
# ---------------------------------------------------------
def ensure_safe_sql_value(value: str) -> str:
    """
    Полная проверка SQL-значения:
    - отсутствие SQL-инъекций
    - отсутствие опасных символов
    - ограничение длины
    Возвращает безопасную строку.
    """
    ensure_no_sql_injection(value)
    return sanitize_sql_input(value)