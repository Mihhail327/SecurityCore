from securitycore._internal.regexes import ADVANCED_PASSWORD_REGEX
from securitycore._internal.constants import SPECIAL_CHARS, MIN_PASSWORD_LENGTH
from securitycore.analysis.entropy import entropy as get_entropy, estimate_charset_size, brute_force_resistance


def password_analyzer(password: str) -> dict:
    """
    Возвращает комплексный аудит безопасности пароля.
    """
    password = password or ""
    length = len(password)

    # Используем наши проверенные функции
    bits_of_entropy = get_entropy(password)
    charset_size = estimate_charset_size(password)
    # Стойкость к брутфорсу (log2 от пространства ключей)
    resistance = brute_force_resistance(password)

    valid_strict = bool(ADVANCED_PASSWORD_REGEX.match(password))
    recommendations = []

    # Анализ длины
    if length < MIN_PASSWORD_LENGTH:
        recommendations.append(f"Критически короткий пароль (минимум {MIN_PASSWORD_LENGTH})")
    elif length < 12:
        recommendations.append("Рекомендуется увеличить длину до 12+ символов для защиты от GPU-перебора")

    # Рекомендации по составу (базируются на размере алфавита)
    # Если размер мал, значит чего-то явно не хватает
    if not any(ch.islower() for ch in password):
        recommendations.append("Добавьте строчные буквы (a-z)")
    if not any(ch.isupper() for ch in password):
        recommendations.append("Добавьте заглавные буквы (A-Z)")
    if not any(ch.isdigit() for ch in password):
        recommendations.append("Добавьте цифры (0-9)")
    if not any(ch in SPECIAL_CHARS for ch in password):
        recommendations.append("Добавьте спецсимволы (напр. !, @, #)")

    # Оценка силы на основе битов стойкости (Resistance)
    # 0-40: Weak, 40-60: Medium, 60-80: Strong, 80+: Very Strong
    if resistance < 40:
        strength = "weak"
    elif resistance < 60:
        strength = "medium"
    elif resistance < 80:
        strength = "strong"
    else:
        strength = "very_strong"

    return {
        "length": length,
        "entropy_per_char": round(bits_of_entropy, 2),
        "brute_force_bits": round(resistance, 2),
        "charset_size": charset_size,
        "strength": strength,
        "valid_strict": valid_strict,
        "recommendations": recommendations,
    }