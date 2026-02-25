import html
from typing import Any, Union

from securitycore._internal.error import ValidationError
from securitycore.utils.patterns import (
    EMAIL_PATTERN,
    URL_PATTERN,
)

def sanitize_string(value: str) -> str:
    """Базовая нормализация строки."""
    if not isinstance(value, str):
        raise ValidationError("Ожидалась строка")

    # Удаляем невидимые символы и null-байты
    cleaned = value.strip().replace("\x00", "")
    return cleaned

def sanitize_email(value: str) -> str:
    """Санитизация email: нормализация + валидация."""
    # Email всегда в нижнем регистре, пробелы не нужны
    email = sanitize_string(value).lower().replace(" ", "")

    if not EMAIL_PATTERN.match(email):
        raise ValidationError("Некорректный формат email")

    return email

def sanitize_url(value: str) -> str:
    """Санитизация URL: валидация ПЕРЕД экранированием."""
    url = sanitize_string(value)

    # Сначала проверяем, что это вообще URL
    if not URL_PATTERN.match(url):
        raise ValidationError("Некорректный формат URL")

    # В библиотеке безопасности лучше вернуть чистый URL,
    # а экранировать его должен слой представления (шаблонизатор)
    return url

def sanitize_text(value: str) -> str:
    """XSS-safe очистка текста для вывода в HTML."""
    cleaned = sanitize_string(value)
    return html.escape(cleaned, quote=True)

def sanitize_int(value: Any) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        raise ValidationError("Некорректное целое число")

# --- УНИВЕРСАЛЬНЫЙ МЕТОД ---

def input_sanitizer(value: Any) -> Union[str, int, float]:
    """
    Универсальный вход для обработки данных.
    """
    if isinstance(value, (int, float)):
        return value

    if not isinstance(value, str):
        raise ValidationError(f"Неподдерживаемый тип: {type(value)}")

    cleaned = sanitize_string(value)
    if not cleaned:
        return ""

    # 1. Проверка на Email (если есть @)
    if "@" in cleaned:
        try:
            return sanitize_email(cleaned)
        except ValidationError:
            pass

    # 2. Проверка на URL
    if cleaned.lower().startswith(("http://", "https://")):
        try:
            return sanitize_url(cleaned)
        except ValidationError:
            pass

    # 3. По умолчанию — безопасный текст
    return sanitize_text(cleaned)