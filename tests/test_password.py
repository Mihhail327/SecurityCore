import pytest
from securitycore.analysis import password_analyzer

# Тесты на сильные пароли

def test_strong_password():
    result = password_analyzer("Abc123!@secure")
    assert result["strength"] == "strong"
    assert result["valid"] is True
    assert result["feedback"] == []


# Тесты на средние пароли

def test_medium_password():
    result = password_analyzer("Abc12345")
    assert result["strength"] == "medium"
    assert result["valid"] is False
    assert "Добавьте спецсимвол" in result["feedback"]


# Тест на слабые пароли

def test_weak_password():
    result = password_analyzer("abc")
    assert result["strength"] == "weak"
    assert result["valid"] is False
    assert "Пароль слишком короткий (<8 символов)" in result["feedback"]


# Тесты на пробелы

def test_password_with_space():
    result = password_analyzer("Abc 123!@")
    assert "Не используйте пробелы в пароле" in result["feedback"]


# Тест на запрещённые символы

def test_password_with_non_printable():
    result = password_analyzer("Abc123!@\u0401") # добавим кириллицу Ё
    assert  "Используйте только латинские буквы и стандартные символы" in result["feedback"]