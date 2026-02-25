from securitycore._internal.error import SecurityViolationError
from securitycore._internal.regexes import (
    SQL_INJECTION_PATTERN,
    SQL_META_CHARS_PATTERN,
)
from securitycore._internal.constants import (
    MAX_SQL_INPUT_LENGTH,
)
# Импортируем наш аудит для фиксации атак
from securitycore.audit.audit_logger import audit

def ensure_no_sql_injection(value: str) -> None:
    """Проверяет строку на наличие признаков SQL-инъекции."""
    if not isinstance(value, str):
        return # Если не строка, то regex не сработает, а инъекция через int невозможна

    if len(value) > MAX_SQL_INPUT_LENGTH:
        raise SecurityViolationError("SQL-параметр превышает лимит длины")

    # Проверка на ключевые слова и конструкции (UNION SELECT и т.д.)
    if SQL_INJECTION_PATTERN.search(value):
        audit("sql_injection_attempt", {"input": value[:50]})
        raise SecurityViolationError("Обнаружена подозрительная SQL-конструкция")

    # Проверка на метасимволы
    if SQL_META_CHARS_PATTERN.search(value):
        raise SecurityViolationError("Строка содержит запрещенные SQL-символы")

def sanitize_sql_input(value: str) -> str:
    """Удаляет метасимволы, оставляя только текст."""
    if not isinstance(value, str):
        raise SecurityViolationError("SQL-параметр должен быть строкой")

    # Удаляем кавычки и прочее, что может сломать запрос
    cleaned = SQL_META_CHARS_PATTERN.sub("", value)
    return cleaned.strip()

def ensure_safe_sql_value(value: str) -> str:
    """Комплексный фильтр для SQL данных."""
    ensure_no_sql_injection(value)
    return sanitize_sql_input(value)