import string

SPECIAL = "!@#$%^&*()-_=+[]{};:,.<>?/\\|"

def analyze_password(password: str) -> dict:
    """
    Анализирует пароль и возвращает результат:
    - strength: уровень сложности (weak, medium, strong)
    -valid: True/False
    -feedback: список рекомендаций
    """
    feedback = []
    score = 0

    # Проверка длины

    if len(password) >= 12:
        score += 2
    elif len(password) >=8:
        score += 1
    else:
        feedback.append("Пароль слишком короткий (<8 символов)")

    # Проверка цифр

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Добавьте хотя бы одну цифру")

    # Проверка заглавных букв

    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Добавьте заглавную букву")

    # Проверка строчных букв

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Добавьте строчную букву")

    # Проверка спецсимволов

    if any(c in SPECIAL for c in password):
        score += 1
    else:
        feedback.append("Добавьте спецсимвол")

    # Проверка пробелов

    if " " in password:
        feedback.append("Не используйте пробелы в пароле")

    # Проверка запрещённых символов (например, кириллица)

    if any(c not in string.printable for c in password):
        feedback.append("Используйте только латинские буквы и стандартные символы")

    # Определение уровня сложности

    if score >= 5:
        strength = "strong"
    elif score >=3:
        strength = "medium"
    else:
        strength = "weak"

    return {
        "strength": strength,
        "valid": strength == "strong",
        "feedback": feedback
    }