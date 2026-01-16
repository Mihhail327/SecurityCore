from securitycore._internal.regexes import ADVANCED_PASSWORD_REGEX
from securitycore._internal.constants import (
    SPECIAL_CHARS,
    MIN_PASSWORD_LENGTH
)
from securitycore.analysis.entropy import calculate_entropy, estimate_charset_size


# Основной анализ пароля
def analyze_password(password: str) -> dict:
    """
    Возвращает подробный анализ пароля:
    - entropy: float
    - charset_size: int
    - length: int
    - strength: weak/medium/strong/very_strong
    - valid_strict: соответствует ли строгому regex
    - recommendations: list[str]
    """
    password = password or ""
    length = len(password)

    entropy = calculate_entropy(password)
    charset_size = estimate_charset_size(password)

    valid_strict = bool(ADVANCED_PASSWORD_REGEX.match(password))

    recommendations = []

    # Длина
    if length < MIN_PASSWORD_LENGTH:
        recommendations.append(f"Увеличьте длину до {MIN_PASSWORD_LENGTH} символов")
    elif length < 12:
        recommendations.append("Рекомендуется длина 12+ символов")

    # Классы символов
    if not any(ch.islower() for ch in password):
        recommendations.append("Добавьте строчные буквы")
    if not any(ch.isupper() for ch in password):
        recommendations.append("Добавьте заглавные буквы")
    if not any(ch.isdigit() for ch in password):
        recommendations.append("Добавьте цифры")
    if not any(ch in SPECIAL_CHARS for ch in password):
        recommendations.append("Добавьте специальные символы")

    # Оценка силы
    if entropy < 28:
        strength = "weak"
    elif entropy < 36:
        strength = "medium"
    elif entropy < 60:
        strength = "strong"
    else:
        strength = "very_strong"

    return {
        "password": password,
        "length": length,
        "entropy": entropy,
        "charset_size": charset_size,
        "strength": strength,
        "valid_strict": valid_strict,
        "recommendations": recommendations,
    }