import re
import html

# Базовые проверки

def strip_whitespace(text: str) -> str:
    """
    Убирает лишние пробелы в начале и конце строки.
    """
    return text.strip()

def remove_control_chars(text: str) -> str:
    """
    Удаляет управляющие символы (например, \n, \r, \t).
    """
    return re.sub(r'[\x00-\x1f\x7f]', '', text)

# Защита от XSS

def escape_html(text: str) -> str:
    """
    Экранирует HTML-символы, чтобы предотвратить XSS
    """
    return html.escape(text)

# Защита от SQL-инъекций

SQL_PATTERNS = [
    r"(?i)\bSELECT\b",
    r"(?i)\bINSERT\b",
    r"(?i)\bUPDATE\b",
    r"(?i)\bDELETE\b",
    r"(?i)\bDROP\b",
    r"(?i)\bUNION\b",
    r"(?i)\bEXEC\b",
    r"(?i)\bALTER\b",
    r"(?i)\bTRUNCATE\b",
    r"(?i)\bCREATE\b",
    r"--", # комментарий SQL

    r";" # множественные запросы
]

def detect_sql_injection(text: str) -> list[str]:
    """
    Проверяет, содержит ли строка подозрительные SQL-паттерны
    """
    return [pattern for pattern in SQL_PATTERNS if re.search(pattern, text)]

# Универсальная очистка

def sanitize_input(text: str) -> dict:
    """
    Полная очистка ввода:
    - убирает пробелы
    - удаляет управляющие символы
    - экранирует HTML
    - проверяет SQL-инъекции
    Возвращает словарь с результатом.
    """
    cleaned = strip_whitespace(text)
    cleaned = remove_control_chars(cleaned)
    safe_html = escape_html(cleaned)

    sql_flag = detect_sql_injection(cleaned)

    is_safe = len(sql_flag) == 0

    return {
        "original": text,
        "cleaned": safe_html,
        "sql_injection_detected": sql_flag,
        "is_safe": is_safe
    }