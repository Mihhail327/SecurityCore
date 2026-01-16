import re

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)

URL_PATTERN = re.compile(
    r"^(https?://)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/.*)?$"
)

USERNAME_PATTERN = re.compile(
    r"^[A-Za-z0-9._-]{3,32}$"
)

PASSWORD_PATTERN = re.compile(
    r"^.{6,}$"
)

PHONE_PATTERN = re.compile(
    r"^\+?[0-9]{7,15}$"
)

DOMAIN_PATTERN = re.compile(
    r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)

IPV4_PATTERN = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)