from securitycore._internal.error import ValidationError
from securitycore._internal.constants import (
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
)
from securitycore._internal.regexes import ADVANCED_PASSWORD_REGEX


def is_password_secure(value: str) -> bool:
    """
    Булева проверка: соответствует ли пароль всем строгим требованиям.
    """
    if not isinstance(value, str):
        return False

    # Проверяем длину без модификации строки
    length = len(value)
    if length < MIN_PASSWORD_LENGTH or length > MAX_PASSWORD_LENGTH:
        return False

    return bool(ADVANCED_PASSWORD_REGEX.match(value))


def validate_password(value: str) -> str:
    """
    Строгая валидация пароля с информативными ошибками.
    """
    if not isinstance(value, str):
        raise ValidationError("Пароль должен быть строкой")

    length = len(value)
    if length < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль слишком короткий (минимум {MIN_PASSWORD_LENGTH} симв.)"
        )

    if length > MAX_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль слишком длинный (максимум {MAX_PASSWORD_LENGTH} симв.)"
        )

    if not ADVANCED_PASSWORD_REGEX.match(value):
        # Здесь можно расширить описание: "нужны цифры, заглавные буквы и т.д."
        raise ValidationError(
            "Пароль не соответствует требованиям сложности (нужны буквы в разных регистрах, цифры и спецсимволы)"
        )

    return value


def ensure_password(value: str) -> str:
    """
    Алиас для основной валидации.
    """
    return validate_password(value)
