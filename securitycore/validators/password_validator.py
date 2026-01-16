from securitycore._internal.error import ValidationError
from securitycore._internal.constants import (
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
)
from securitycore._internal.regexes import ADVANCED_PASSWORD_REGEX
from securitycore.utils.patterns import PASSWORD_PATTERN


# Лёгкая проверка пароля
def is_password(value: str) -> bool:
    """
    Быстрая проверка пароля:
    - минимальная длина
    - буквы + цифры
    - базовые спецсимволы
    Использует PASSWORD_PATTERN из utils.patterns.
    """
    if not isinstance(value, str):
        return False

    value = value.strip()

    if len(value) < MIN_PASSWORD_LENGTH or len(value) > MAX_PASSWORD_LENGTH:
        return False

    return PASSWORD_PATTERN.match(value) is not None


# Строгая проверка пароля
def validate_password(value: str) -> str:
    """
    Строгая проверка пароля:
    - длина
    - классы символов
    - спецсимволы
    - отсутствие пробелов
    Использует ADVANCED_PASSWORD_REGEX.
    """
    if not isinstance(value, str):
        raise ValidationError("Пароль должен быть строкой")

    value = value.strip()

    if len(value) < MIN_PASSWORD_LENGTH:
        raise ValidationError("Пароль слишком короткий")

    if len(value) > MAX_PASSWORD_LENGTH:
        raise ValidationError("Пароль слишком длинный")

    if not ADVANCED_PASSWORD_REGEX.match(value):
        raise ValidationError("Пароль не соответствует требованиям безопасности")

    return value


# Универсальная проверка
def ensure_password(value: str) -> str:
    """
    Универсальная проверка:
    - сначала лёгкая проверка (PASSWORD_PATTERN)
    - затем строгая проверка (ADVANCED_PASSWORD_REGEX)
    """
    if not is_password(value):
        raise ValidationError("Пароль не соответствует базовым требованиям")

    return validate_password(value)