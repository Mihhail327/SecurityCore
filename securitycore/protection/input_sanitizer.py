import html
import re

from securitycore._internal.error import ValidationError
from securitycore.utils.patterns import (
    EMAIL_PATTERN,
    URL_PATTERN,
)


# Общий санитайзер строки
def sanitize_string(value: str) -> str:
    """
    Очищает строку от управляющих символов и лишних пробелов.
    Не изменяет смысл, только нормализует.
    """
    if not isinstance(value, str):
        raise ValidationError("Ожидалась строка")

    cleaned = value.strip()
    cleaned = cleaned.replace("\x00", "")  # null-byte protection
    return cleaned


# Санитайзер email
def sanitize_email(value: str) -> str:
    """
    Нормализует email:
    - убирает пробелы
    - приводит к нижнему регистру
    - проверяет по лёгкому EMAIL_PATTERN
    """
    value = sanitize_string(value).lower()

    if not EMAIL_PATTERN.match(value):
        raise ValidationError("Некорректный email")

    return value


# Санитайзер URL
def sanitize_url(value: str) -> str:
    """
    Нормализует URL:
    - убирает пробелы
    - HTML-экранирует
    - проверяет по лёгкому URL_PATTERN
    """
    value = sanitize_string(value)
    value = html.escape(value, quote=True)

    if not URL_PATTERN.match(value):
        raise ValidationError("Некорректный URL")

    return value


# Санитайзер для безопасного текста (XSS-safe)
def sanitize_text(value: str) -> str:
    """
    Экранирует HTML, удаляет опасные символы.
    Подходит для отображения пользовательского ввода.
    """
    if not isinstance(value, str):
        raise ValidationError("Ожидалась строка")

    value = value.replace("\x00", "")
    return html.escape(value, quote=True)


# Санитайзер для чисел
def sanitize_int(value) -> int:
    """
    Преобразует значение в int.
    """
    try:
        return int(value)
    except Exception:
        raise ValidationError("Некорректное целое число")


def sanitize_float(value) -> float:
    """
    Преобразует значение в float.
    """
    try:
        return float(value)
    except Exception:
        raise ValidationError("Некорректное число с плавающей точкой")