import html
import nh3

from securitycore._internal.error import SecurityViolationError
from securitycore._internal.constants import MAX_INPUT_LENGTH
from securitycore.audit.audit_logger import audit


class SafeString(str):
    """
    Класс-обертка, обозначающий, что строка безопасна для рендеринга (XSS-safe).
    """

    pass


def ensure_no_xss(value: str) -> None:
    """
    Проверка на XSS векторы (IDS режим).
    Вместо агрессивной блокировки мы логгируем попытки и блокируем явно опасные скрипты.
    """
    if not isinstance(value, str):
        return

    if len(value) > MAX_INPUT_LENGTH:
        raise SecurityViolationError("Ввод слишком длинный")

    # Детектируем наличие скриптов или опасных атрибутов
    if (
        "<script" in value.lower()
        or "javascript:" in value.lower()
        or "onerror=" in value.lower()
    ):
        audit("xss_attempt", {"payload": value[:100]})
        raise SecurityViolationError("Обнаружен запрещенный HTML-тег (XSS риск)")


def sanitize_xss(value: str, strict: bool = False) -> SafeString:
    """
    Очистка и экранирование HTML с использованием nh3.
    Если strict=True, полностью вырезает весь HTML (возвращает только текст).
    Иначе удаляет только XSS-векторы, оставляя безопасные теги (если нужно).
    """
    if not isinstance(value, str):
        raise SecurityViolationError("Ожидалась строка")

    if strict:
        # Полное удаление тегов и экранирование спецсимволов
        cleaned = nh3.clean(value, tags=set())
        # nh3 может оставлять экранированные энтити, используем html.escape для надежности
        return SafeString(html.escape(cleaned, quote=True).strip())

    # Дефолтная очистка nh3 убирает XSS, но может оставить <b>, <i> и тд.
    cleaned = nh3.clean(value)
    return SafeString(cleaned.strip())
