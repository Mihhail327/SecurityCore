import re


# Email (упрощённый, но практичный)
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)


# URL (http/https, домен, путь, параметры)
URL_PATTERN = re.compile(
    r"^(https?://)"
    r"([A-Za-z0-9.-]+)"
    r"(:\d+)?"
    r"(/.*)?$"
)


# IPv4
IPV4_PATTERN = re.compile(
    r"^("
    r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)


# IPv6 (упрощённый, но рабочий)
IPV6_PATTERN = re.compile(
    r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
)


# Пароль (минимум 8 символов, буквы + цифры)
PASSWORD_PATTERN = re.compile(
    r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*()_\-+=]{8,}$"
)


# Имя пользователя (буквы, цифры, _, -, 3–32 символа)
USERNAME_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]{3,32}$"
)


# Домен (example.com)
DOMAIN_PATTERN = re.compile(
    r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)


# UUID v4
UUID4_PATTERN = re.compile(
    r"^[a-f0-9]{8}-"
    r"[a-f0-9]{4}-"
    r"4[a-f0-9]{3}-"
    r"[89ab][a-f0-9]{3}-"
    r"[a-f0-9]{12}$",
    re.IGNORECASE
)

