from securitycore._internal.error import ValidationError
from securitycore._internal.constants import MAX_IP_LENGTH
from securitycore._internal.regexes import (
    IPV4_REGEX,
    FULL_IPV6_REGEX,
)
from securitycore.utils.patterns import IPV4_PATTERN


# Лёгкая проверка IPv4
def is_ipv4(value: str) -> bool:
    if not isinstance(value, str):
        return False

    value = value.strip()

    if len(value) > MAX_IP_LENGTH:
        return False

    return IPV4_PATTERN.match(value) is not None


# Строгая проверка IPv4
def validate_ipv4(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("IPv4 должен быть строкой")

    value = value.strip()

    if len(value) > MAX_IP_LENGTH:
        raise ValidationError("IPv4 слишком длинный")

    if not IPV4_REGEX.match(value):
        raise ValidationError("Некорректный IPv4-адрес")

    return value


# Строгая проверка IPv6
def validate_ipv6(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("IPv6 должен быть строкой")

    value = value.strip()

    if len(value) > MAX_IP_LENGTH:
        raise ValidationError("IPv6 слишком длинный")

    if not FULL_IPV6_REGEX.match(value):
        raise ValidationError("Некорректный IPv6-адрес")

    return value


# Булевы проверки IPv4/IPv6
def is_valid_ipv4(value: str) -> bool:
    try:
        validate_ipv4(value)
        return True
    except ValidationError:
        return False


def is_valid_ipv6(value: str) -> bool:
    try:
        validate_ipv6(value)
        return True
    except ValidationError:
        return False


# Универсальная проверка IP
def ensure_ip(value: str) -> str:
    if is_ipv4(value):
        return validate_ipv4(value)

    try:
        return validate_ipv6(value)
    except ValidationError:
        raise ValidationError("Некорректный IP-адрес")


# Универсальная строгая проверка IP
def validate_ip(value: str) -> None:
    if is_valid_ipv4(value):
        return
    if is_valid_ipv6(value):
        return
    raise ValidationError("Некорректный IP-адрес")