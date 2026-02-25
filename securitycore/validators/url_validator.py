from securitycore._internal.error import ValidationError
from securitycore._internal.constants import MAX_URL_LENGTH
from securitycore._internal.regexes import ADVANCED_URL_REGEX

def is_valid_url(value: str) -> bool:
    """Булева проверка: валиден ли URL по строгим правилам."""
    if not isinstance(value, str):
        return False
    value = value.strip()
    return len(value) <= MAX_URL_LENGTH and bool(ADVANCED_URL_REGEX.match(value))

def validate_url(value: str) -> str:
    """Строгая валидация URL."""
    if not isinstance(value, str):
        raise ValidationError("URL должен быть строкой")

    clean_url = value.strip()

    if len(clean_url) > MAX_URL_LENGTH:
        raise ValidationError(f"URL слишком длинный (макс. {MAX_URL_LENGTH} симв.)")

    if not ADVANCED_URL_REGEX.match(clean_url):
        raise ValidationError("Некорректный формат URL (поддерживаются http/https)")

    return clean_url

def ensure_url(value: str) -> str:
    """Универсальный алиас для валидации."""
    return validate_url(value)