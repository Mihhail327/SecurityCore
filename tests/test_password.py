from securitycore.analysis.password_analyzer import password_analyzer


# Тесты на сильные пароли
def test_strong_password():
    # Пароль с хорошим набором символов и длиной
    result = password_analyzer("Abc123!@secure")

    # В нашей логике это либо strong, либо very_strong
    assert result["strength"] in ["strong", "very_strong"]
    assert result["valid_strict"] is True
    assert result["recommendations"] == []


# Тесты на средние пароли
def test_medium_password():
    # Пароль без спецсимволов
    result = password_analyzer("Abc123456789")

    assert result["valid_strict"] is False
    # Проверяем, что в рекомендациях есть совет про спецсимволы
    assert any("спецсимволы" in rec for rec in result["recommendations"])


# Тест на слабые пароли
def test_weak_password():
    result = password_analyzer("abc")

    assert result["strength"] == "weak"
    assert result["valid_strict"] is False
    assert any("короткий" in rec for rec in result["recommendations"])


# Тесты на нетипичные символы (Кириллица)
def test_password_with_non_ascii():
    # Наш ADVANCED_PASSWORD_REGEX работает только с A-Za-z и SPECIAL_CHARS
    result = password_analyzer("Abc123!@Ё")

    # Он не пройдет строгую проверку регуляркой
    assert result["valid_strict"] is False


# Тест на пустой ввод
def test_password_empty():
    result = password_analyzer("")
    assert result["length"] == 0
    assert result["strength"] == "weak"
