import warnings
from securitycore._internal.error import SecurityViolationError
from securitycore._internal.regexes import (
    SQL_INJECTION_PATTERN,
)
from securitycore._internal.constants import (
    MAX_SQL_INPUT_LENGTH,
)
from securitycore.audit.audit_logger import audit


def ensure_no_sql_injection(value: str) -> None:
    """
    [IDS Layer] Проверяет строку на наличие признаков SQL-инъекции.
    ВНИМАНИЕ: Это не заменяет параметризованные запросы!
    Используйте это как WAF/IDS для аудита попыток взлома.
    """
    if not isinstance(value, str):
        return

    if len(value) > MAX_SQL_INPUT_LENGTH:
        raise SecurityViolationError("SQL-параметр превышает лимит длины")

    # Проверка на ключевые слова и конструкции (UNION SELECT и т.д.)
    if SQL_INJECTION_PATTERN.search(value):
        audit("sql_injection_attempt", {"input": value[:50]})
        # Логгируем, но не падаем жестко на всех символах,
        # падаем только если паттерн явно злонамеренный.
        raise SecurityViolationError("Обнаружена подозрительная SQL-конструкция")


def sanitize_sql_input(value: str) -> str:
    """
    [Legacy] Удаляет метасимволы.
    ВНИМАНИЕ: Использование этой функции не защищает от сложных инъекций.
    Она может сломать легитимные данные (например, "O'Connor").
    Лучшая практика - использовать Prepared Statements в вашей ORM.
    """
    warnings.warn(
        "sanitize_sql_input угасает (deprecated). Динамическая ручная санитизация SQL не гарантирует "
        "защиту от SQL-инъекций. Используйте параметризованные запросы / ORM.",
        DeprecationWarning,
        stacklevel=2,
    )
    if not isinstance(value, str):
        raise SecurityViolationError("SQL-параметр должен быть строкой")

    cleaned = value.replace("--", "").replace("/*", "").replace("*/", "")
    return cleaned.strip()


def ensure_safe_sql_value(value: str) -> str:
    """Комплексный фильтр для SQL данных (IDS + базовая очистка)."""
    ensure_no_sql_injection(value)
    return sanitize_sql_input(value)
