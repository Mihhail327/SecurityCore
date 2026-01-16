import re

from securitycore._internal.error import ValidationError
from securitycore._internal.constants import MAX_EMAIL_LENGTH
from securitycore._internal.regexes import RFC5322_EMAIL_REGEX
from securitycore.utils.patterns import EMAIL_PATTERN


# Лёгкая проверка email (быстрая
def is_email(value: str) -> bool:
    """
    Быстрая проверка email с использованием лёгкого паттаерна.
    Подходит для форм, UI, первичной валидации.
    """
    if not isinstance(value, str):
        return False

    if len(value) > MAX_EMAIL_LENGTH:
        return False

    return EMAIL_PATTERN.match(value) is not None


# Строгая проверка email (RFC 5322)
def validate_email(value: str) -> str:
    """
    Строгая проверка email по RFC 5322.
    Используется для безопасности, анализа, критичных операций.
    """
    if not isinstance(value, str):
        raise ValidationError("Email должен быть строкой")

    if len(value) > MAX_EMAIL_LENGTH:
        raise ValidationError("Email слишком длинный")

    if not RFC5322_EMAIL_REGEX.match(value):
        raise ValidationError("Некорректный email (RFC 5322)")

    return value


# Универсальная функция
def ensure_email(value: str) -> str:
    """
    Универсальная проверка email:
    - сначала лёгкая проверка
    - затем строгая RFC-проверка
    """
    if not is_email(value):
        raise ValidationError("Некорректный email")

    return validate_email(value)