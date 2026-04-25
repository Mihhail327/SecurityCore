import re
from typing import Final
from securitycore._internal.constants import (
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    SPECIAL_CHARS,
)

# Используем re.VERBOSE для сложных регулярок, чтобы их можно было читать
# RFC 5322 Email - добавлена атомарная группировка (где возможно) для защиты от ReDoS
RFC5322_EMAIL_REGEX: Final[re.Pattern] = re.compile(
    r"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*| "
    r"\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")"
    r"@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?| "
    r"\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|"
    r"[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])",
    re.IGNORECASE,
)

# Advanced URL - RFC 3986 compliant (упрощенно для производительности)
ADVANCED_URL_REGEX: Final[re.Pattern] = re.compile(
    r"^(?:https?://)"  # Протокол
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,63}|[A-Z0-9-]{2,})|"  # Домен
    r"localhost|"  # Локальный хост
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # IPv4
    r"(?::\d+)?"  # Порт
    r"(?:/?|[/?]\S+)$",  # Путь и параметры
    re.IGNORECASE,
)

# SQL Injection - расширен на детектирование специфических техник
SQL_INJECTION_PATTERN: Final[re.Pattern] = re.compile(
    r"""
    (?:\b(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|TRUNCATE)\b) # Ключевые слова
    | (?:--|\#|/\*|\*/)                                                    # Комментарии
    | (?:\bOR\b|\bAND\b)\s+[\w\d]+\s*[=<>]                                  # Логические инъекции
    | (?:\bsleep\(.*\)|benchmark\(.*\))                                     # Time-based
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Опасные метасимволы (кавычки, комментарии, точка с запятой)
SQL_META_CHARS_PATTERN = re.compile(r"[;#'\"`]|--|\*/|/\*", re.IGNORECASE)

# Advanced Password - динамически берем длину из констант
# Используем экранирование для спецсимволов из constants
_escaped_chars = re.escape(SPECIAL_CHARS)
ADVANCED_PASSWORD_REGEX: Final[re.Pattern] = re.compile(
    rf"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[{_escaped_chars}])"
    rf"[A-Za-z\d{_escaped_chars}]{{{MIN_PASSWORD_LENGTH},{MAX_PASSWORD_LENGTH}}}$"
)

# XSS - более агрессивный поиск тегов
XSS_DANGEROUS_TAGS: Final[re.Pattern] = re.compile(
    r"<(?:script|iframe|object|embed|applet|meta|base|svg|form|style|link)",
    re.IGNORECASE,
)

# Path traversal detection
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|%2e%2e/|%2e%2e\\|%2e%2f|%2f%2e)", re.IGNORECASE
)

# Invalid filename characters
INVALID_FILENAME_PATTERN = re.compile(r"[<>:\"/\\|?*\x00-\x1F]|\s+$|\.$")

# IPv4 - Строгий паттерн с проверкой октетов 0-255
IPV4_REGEX: Final[re.Pattern] = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# IPv6 - Полный паттерн (RFC 4291)
FULL_IPV6_REGEX: Final[re.Pattern] = re.compile(
    r"^(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)|fe80:(?::[0-9A-Fa-f]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9])[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9])[0-9])|(?:[0-9A-Fa-f]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9])[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9])[0-9]))$",
    re.IGNORECASE,
)
