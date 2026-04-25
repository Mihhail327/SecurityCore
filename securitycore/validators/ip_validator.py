import ipaddress
from securitycore._internal.error import ValidationError
from securitycore._internal.constants import MAX_IP_LENGTH
from securitycore._internal.regexes import (
    IPV4_REGEX,
    FULL_IPV6_REGEX,
)


def is_ipv4(value: str) -> bool:
    """Лёгкая проверка IPv4."""
    if not isinstance(value, str):
        return False
    value = value.strip()
    return len(value) <= MAX_IP_LENGTH and bool(IPV4_REGEX.match(value))


def validate_ipv4(value: str) -> str:
    """Строгая проверка IPv4 через regex + ipaddress."""
    if not isinstance(value, str):
        raise ValidationError("IPv4 должен быть строкой")

    value = value.strip()
    try:
        # Проверяем не только формат, но и валидность адреса как объекта
        ipaddress.IPv4Address(value)
        return value
    except ValueError:
        raise ValidationError("Некорректный IPv4-адрес")


def validate_ipv6(value: str) -> str:
    """Строгая проверка IPv6 (Regex + IPAddress)."""
    if not isinstance(value, str):
        raise ValidationError("IPv6 должен быть строкой")

    # Сначала очищаем от пробелов
    clean_value = value.strip()

    # 1. Проверка формата через твой FULL_IPV6_REGEX
    if not FULL_IPV6_REGEX.match(clean_value):
        raise ValidationError("Формат IPv6 не соблюден")

    # 2. Проверка логики адреса через стандартную библиотеку
    try:
        ipaddress.IPv6Address(clean_value)
        return clean_value
    except ValueError:
        raise ValidationError("Логическая ошибка в IPv6 адресе")


def validate_ip(value: str) -> str:
    """Универсальная строгая проверка IP."""
    try:
        # Пытаемся распарсить как любой IP
        ipaddress.ip_address(value.strip())
        return value.strip()
    except ValueError:
        raise ValidationError("Некорректный IP-адрес (не IPv4 и не IPv6)")
