import re


# RFC 5322 Email (расширенный)

# Это более строгий и совместимый шаблон, чем упрощённый EMAIL_PATTERN.
# Используется для глубоких проверок, анализа и тестов.
RFC5322_EMAIL_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*|"
    r"\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-"
    r"\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@"
    r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}|"
    r"\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|"
    r"[a-zA-Z0-9-]*[a-zA-Z0-9]:"
    r"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]"
    r"|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)])$"
)


# URL (расширенный, с поддержкой query, fragment, IPv4/IPv6)
ADVANCED_URL_REGEX = re.compile(
    r"^(https?://)"
    r"("
    r"([A-Za-z0-9.-]+)|"          # домен
    r"(\[[0-9a-fA-F:]+\])"        # IPv6
    r")"
    r"(:\d{1,5})?"                # порт
    r"(/[A-Za-z0-9._~!$&'()*+,;=:@%-/]*)?"  # путь
    r"(\?[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?" # query
    r"(#[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?$" # fragment
)


# IPv6 (полная поддержка всех форм)
FULL_IPV6_REGEX = re.compile(
    r"^("
    r"([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
    r"([0-9A-Fa-f]{1,4}:){1,7}:|"
    r"([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|"
    r"([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|"
    r"([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|"
    r"([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|"
    r"([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|"
    r"[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})|"
    r":((:[0-9A-Fa-f]{1,4}){1,7}|:)|"
    r"fe80:(:[0-9A-Fa-f]{0,4}){0,4}%[0-9A-Za-z]{1,}|"
    r"::(ffff(:0{1,4}){0,1}:){0,1}"
    r"((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3}"
    r"(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])|"
    r"([0-9A-Fa-f]{1,4}:){1,4}:"
    r"((25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])\.){3}"
    r"(25[0-5]|(2[0-4]|1{0,1}[0-9])?[0-9])"
    r")$"
)


# Пароль (расширенный, с классами символов)
ADVANCED_PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])"               # строчные
    r"(?=.*[A-Z])"                # заглавные
    r"(?=.*\d)"                   # цифры
    r"(?=.*[!@#$%^&*()_\-+=\[\]{};:,.<>?/\\|])"  # спецсимволы
    r"[A-Za-z\d!@#$%^&*()_\-+=\[\]{};:,.<>?/\\|]{12,}$"
)


# Path traversal detection
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|%2e%2e/|%2e%2e\\|%2e%2f|%2f%2e)",
    re.IGNORECASE
)

# Invalid filename characters
INVALID_FILENAME_PATTERN = re.compile(
    r"[<>:\"/\\|?*\x00-\x1F]|\s+$|\.$"
)


# SQL injection detection
SQL_INJECTION_PATTERN = re.compile(
    r"""
    (--|#|/\*|\*/|;)                     # комментарии и разделители
    |'                                   # одиночная кавычка
    |(\bOR\b|\bAND\b)\s+\d+=\d+          # логические выражения
    |\bUNION\b\s+\bSELECT\b              # UNION SELECT
    |\bDROP\b\s+\bTABLE\b                # DROP TABLE
    |\bINSERT\b\s+\bINTO\b               # INSERT INTO
    |\bUPDATE\b\s+\bSET\b                # UPDATE SET
    |\bDELETE\b\s+\bFROM\b               # DELETE FROM
    """,
    re.IGNORECASE | re.VERBOSE
)

# Dangerous SQL meta-characters
SQL_META_CHARS_PATTERN = re.compile(
    r"[;#'\"`]|--|\*/|/\*",
    re.IGNORECASE
)


# <script>...</script>
XSS_SCRIPT_PATTERN = re.compile(
    r"<\s*script.*?>.*?<\s*/\s*script\s*>",
    re.IGNORECASE | re.DOTALL
)

# onload=, onclick=, onerror=, onfocus= и т.д.
XSS_EVENT_HANDLER_PATTERN = re.compile(
    r"on\w+\s*=",
    re.IGNORECASE
)

# javascript:alert(1)
XSS_JS_PROTOCOL_PATTERN = re.compile(
    r"javascript\s*:",
    re.IGNORECASE
)


IPV4_REGEX = re.compile(
    r"^("
    r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)