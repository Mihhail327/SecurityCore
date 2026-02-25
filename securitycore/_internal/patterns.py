import re
from typing import Final
from securitycore._internal.constants import (
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    MAX_EMAIL_LENGTH,
)

# Email: Соответствует RFC 5322 в упрощенном виде, ограничен по длине
EMAIL_PATTERN: Final[re.Pattern] = re.compile(
    rf"^(?=[^@]{{1,64}}@.{1, {MAX_EMAIL_LENGTH}}$)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{{2,}}$"
)

# URL: Защищенная версия для http/https
URL_PATTERN: Final[re.Pattern] = re.compile(
    r"^https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s]*)?$"
)

# Username: от 3 до 32 символов (согласно константам, если добавишь)
USERNAME_PATTERN: Final[re.Pattern] = re.compile(r"^[A-Za-z0-9._-]{3,32}$")

# Password: Используем значение из констант. Минимум 8, максимум 128.
# Здесь проверяем только длину, сложность проверит password_validator.
PASSWORD_PATTERN: Final[re.Pattern] = re.compile(
    rf"^.{{{MIN_PASSWORD_LENGTH},{MAX_PASSWORD_LENGTH}}}$"
)

# IPv4: Строгая проверка октетов (0-255)
IPV4_PATTERN: Final[re.Pattern] = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# Phone: Международный формат
PHONE_PATTERN: Final[re.Pattern] = re.compile(r"^\+?[1-9]\d{6,14}$")

# Domain
DOMAIN_PATTERN: Final[re.Pattern] = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,})+$"
)
