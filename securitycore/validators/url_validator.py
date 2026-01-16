from securitycore._internal.error import ValidationError
from securitycore._internal.constants import MAX_URL_LENGTH
from securitycore._internal.regexes import ADVANCED_URL_REGEX
from securitycore.utils.patterns import URL_PATTERN


# Лёгкая проверка URL
def is_url(value: str) -> bool:
    """
    Быстрая проверка URL:
    - проверяет базовый формат
    - подходит для UI, форм, первичной фильтрации
    Использует лёгкий паттерн из utils.patterns.
    """
    if not isinstance(value, str):
        return False

    value = value.strip()

    if len(value) > MAX_URL_LENGTH:
        return False

    return URL_PATTERN.match(value) is not None


# Строгая проверка URL
def validate_url(value: str) -> str:
    """
    Строгая проверка URL:
    - поддержка http/https
    - поддержка IPv4/IPv6
    - поддержка query, fragment
    - строгий синтаксис
    Использует ADVANCED_URL_REGEX из _internal.regexes.
    """
    if not isinstance(value, str):
        raise ValidationError("URL должен быть строкой")

    value = value.strip()

    if len(value) > MAX_URL_LENGTH:
        raise ValidationError("URL слишком длинный")

    if not ADVANCED_URL_REGEX.match(value):
        raise ValidationError("Некорректный URL")

    return value


# Универсальная проверка
def ensure_url(value: str) -> str:
    """
    Универсальная проверка URL:
    - сначала лёгкая проверка
    - затем строгая проверка
    """
    if not is_url(value):
        raise ValidationError("Некорректный URL")

    return validate_url(value)