import re

# Email

def is_valid_email(email: str) -> bool:
    """
    Проверяем корректность email-адреса.
    """
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None

# URL

def is_valid_url(url: str) -> bool:
    """
    Проверяет корректность URL.
    """
    patter = r"^(https?|ftp)://[^\s/$.&#].[^\s]*$"
    return re.match(patter, url) is not None

# Телефон

def is_valid_phone(phone: str) -> bool:
    """
    Проверяет корректность телефонного номера (международный формат).
    """
    pattern = r"^\+?[0-9]{7,15}$"
    return re.match(pattern, phone) is not None

# Пароль

def is_valid_password(password: str) -> bool:
    """
    Проверяет базовые требования к паролю:
    - минимум 8 символов
    - хотя бы одна цифра
    - хотя бы одна заглавная буква
    - хотя бы одна строчная буква
    - хотя бы один спецсимвол
    """
    if len(password) < 8:
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c in "!@#$%^&*()-_=+" for c in password):
        return False
    return True

# IP-адрес

def is_valid_ip(ip: str) -> bool:
    """
    Проверяет корректность IPv4-адреса.
    """
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(part) <= 255 for part in parts)