import re

from securitycore._internal.regexes import (
    RFC5322_EMAIL_REGEX as EMAIL_PATTERN,
    ADVANCED_URL_REGEX as URL_PATTERN,
    IPV4_REGEX as IPV4_PATTERN,
    FULL_IPV6_REGEX as IPV6_PATTERN,
    ADVANCED_PASSWORD_REGEX as PASSWORD_PATTERN,
)

# Имя пользователя (буквы, цифры, _, -, 3–32 символа)
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,32}$")

# Домен (example.com)
DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# UUID v4
UUID4_PATTERN = re.compile(
    r"^[a-f0-9]{8}-"
    r"[a-f0-9]{4}-"
    r"4[a-f0-9]{3}-"
    r"[89ab][a-f0-9]{3}-"
    r"[a-f0-9]{12}$",
    re.IGNORECASE,
)

__all__ = [
    "EMAIL_PATTERN",
    "URL_PATTERN",
    "IPV4_PATTERN",
    "IPV6_PATTERN",
    "PASSWORD_PATTERN",
    "USERNAME_PATTERN",
    "DOMAIN_PATTERN",
    "UUID4_PATTERN",
]

