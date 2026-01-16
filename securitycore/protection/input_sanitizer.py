import html

from securitycore._internal.error import ValidationError
from securitycore.utils.patterns import (
    EMAIL_PATTERN,
    URL_PATTERN,
)


#  БАЗОВЫЕ САНИТАЙЗЕРЫ
def sanitize_string(value: str) -> str:
    """
    Базовая нормализация строки:
    - удаляет пробелы по краям
    - убирает null-byte (\x00)
    - гарантирует, что вход — строка
    """
    if not isinstance(value, str):
        raise ValidationError("Ожидалась строка")

    cleaned = value.strip()
    cleaned = cleaned.replace("\x00", "")  # защита от null-byte injection
    return cleaned


def sanitize_email(value: str) -> str:
    """
    Санитизация email:
    - нормализует строку
    - приводит к нижнему регистру
    - проверяет по EMAIL_PATTERN
    """
    value = sanitize_string(value).lower()

    if not EMAIL_PATTERN.match(value):
        raise ValidationError("Некорректный email")

    return value


def sanitize_url(value: str) -> str:
    """
    Санитизация URL:
    - нормализует строку
    - HTML‑экранирует (защита от XSS)
    - проверяет по URL_PATTERN
    """
    value = sanitize_string(value)
    value = html.escape(value, quote=True)

    if not URL_PATTERN.match(value):
        raise ValidationError("Некорректный URL")

    return value


def sanitize_text(value: str) -> str:
    """
    Санитизация произвольного текста:
    - удаляет null-byte
    - HTML‑экранирует весь текст

    Подходит для безопасного отображения пользовательского ввода (XSS‑safe).
    """
    if not isinstance(value, str):
        raise ValidationError("Ожидалась строка")

    value = value.replace("\x00", "")
    return html.escape(value, quote=True)


def sanitize_int(value) -> int:
    """
    Приведение к целому числу.
    Любая ошибка → ValidationError.
    """
    try:
        return int(value)
    except Exception:
        raise ValidationError("Некорректное целое число")


def sanitize_float(value) -> float:
    """
    Приведение к числу с плавающей точкой.
    Любая ошибка → ValidationError.
    """
    try:
        return float(value)
    except Exception:
        raise ValidationError("Некорректное число с плавающей точкой")



#  УНИВЕРСАЛЬНЫЙ САНИТАЙЗЕР
def input_sanitizer(value):
    """
    Универсальный санитайзер пользовательского ввода.

    Логика:
    - если число → привести к числу
    - если строка:
        - нормализовать
        - попытаться распознать email
        - попытаться распознать URL
        - иначе — безопасный текст (XSS‑safe)
    - иначе → ValidationError
    """

    # Числа
    if isinstance(value, int):
        return sanitize_int(value)

    if isinstance(value, float):
        return sanitize_float(value)

    # Строки
    if isinstance(value, str):
        cleaned = sanitize_string(value)

        # Попытка распознать email
        if "@" in cleaned and "." in cleaned:
            try:
                return sanitize_email(cleaned)
            except ValidationError:
                # не email — продолжаем дальше
                pass

        # Попытка распознать URL
        if cleaned.startswith(("http://", "https://")):
            try:
                return sanitize_url(cleaned)
            except ValidationError:
                # не URL — продолжаем дальше
                pass

        # Обычный текст (XSS‑safe)
        return sanitize_text(cleaned)

    # Всё остальное — ошибка
    raise ValidationError("Неподдерживаемый тип данных для санитизации")